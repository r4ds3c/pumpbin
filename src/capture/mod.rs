//! Capture ingest: PCAP / PcapNG / carve / Pcap-over-IP / live.

pub mod carver;
pub mod etl;
pub mod live;
pub mod packetcache;
pub mod pcap_over_ip;

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;

use crate::case::Case;
use crate::decode::{self, DecodeState};
use crate::reassembly::SessionTracker;

#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub keywords: String,
    pub defang_executables: bool,
    pub enrich: crate::enrich::EnrichConfig,
    pub decode_as: crate::fingerprint::DecodeAsMap,
    pub cidr_filter: String,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            keywords: String::new(),
            defang_executables: true,
            enrich: crate::enrich::EnrichConfig::default(),
            decode_as: crate::fingerprint::DecodeAsMap::builtin(),
            cidr_filter: String::new(),
        }
    }
}

/// Ingest a capture file into a host-centric case.
pub fn ingest_file(path: &Path, output_dir: &Path, opts: &IngestOptions) -> Result<Case> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "pcapng" | "pcap" | "cap" => {}
        "etl" => {
            return etl::ingest_etl(path, output_dir, opts);
        }
        // Memory dumps / unstructured blobs → carver
        "bin" | "dump" | "mem" | "raw" | "img" | "vmem" => {
            return carver::carve_file(path, output_dir, opts);
        }
        _ => {}
    }

    // Sniff ETL magic even without .etl extension
    {
        use std::io::Read;
        if let Ok(mut f) = File::open(path) {
            let mut head = [0u8; 16];
            if f.read(&mut head).unwrap_or(0) >= 8 && etl::looks_like_etl(&head) {
                return etl::ingest_etl(path, output_dir, opts);
            }
        }
    }

    let mut case = Case {
        source_path: Some(path.to_path_buf()),
        ..Case::default()
    };

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    let mut tracker = SessionTracker::new();
    let mut state = DecodeState::new();
    let keyword_list = parse_keywords_pub(&opts.keywords);

    match ext.as_str() {
        "pcapng" => ingest_pcapng(
            path,
            &mut case,
            &mut tracker,
            &mut state,
            output_dir,
            opts.defang_executables,
            &keyword_list,
        )?,
        _ => ingest_pcap(
            path,
            &mut case,
            &mut tracker,
            &mut state,
            output_dir,
            opts.defang_executables,
            &keyword_list,
        )?,
    }

    case.sessions = tracker.into_sessions();
    decode::finalize(&mut case, &mut state, output_dir)?;
    finish_case(&mut case, opts, &state)?;
    Ok(case)
}

fn finish_case(
    case: &mut Case,
    opts: &IngestOptions,
    state: &DecodeState,
) -> Result<()> {
    crate::intel::postprocess(case, &opts.enrich, &opts.decode_as, &state.pipi_hints)?;
    let cidrs = crate::intel::parse_cidr_list(&opts.cidr_filter)?;
    crate::intel::apply_cidr_filter(case, &cidrs);
    Ok(())
}

pub(crate) fn finalize_ingest(
    case: &mut Case,
    opts: &IngestOptions,
    state: &DecodeState,
) -> Result<()> {
    finish_case(case, opts, state)
}

/// Ingest raw Ethernet (or IP) frames — used by live sniff batches and carver paths.
pub fn ingest_frames(
    frames: &[Vec<u8>],
    frame_offset: u64,
    output_dir: &Path,
    opts: &IngestOptions,
) -> Result<Case> {
    let mut case = Case::default();
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;
    let mut tracker = SessionTracker::new();
    let mut state = DecodeState::new();
    let keywords = parse_keywords_pub(&opts.keywords);
    for (i, frame) in frames.iter().enumerate() {
        decode::process_frame(
            &mut case,
            &mut tracker,
            &mut state,
            output_dir,
            opts.defang_executables,
            &keywords,
            frame_offset + i as u64 + 1,
            0.0,
            frame,
        )?;
    }
    case.sessions = tracker.into_sessions();
    decode::finalize(&mut case, &mut state, output_dir)?;
    finish_case(&mut case, opts, &state)?;
    Ok(case)
}

pub fn parse_keywords_pub(raw: &str) -> Vec<KeywordPattern> {
    raw.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let bytes = hex::decode_bytes(hex);
                KeywordPattern::Hex(s.to_string(), bytes)
            } else {
                KeywordPattern::Text(s.to_string())
            }
        })
        .collect()
}

pub enum KeywordPattern {
    Text(String),
    Hex(String, Vec<u8>),
}

mod hex {
    pub fn decode_bytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(clean.get(i..i + 2)?, 16).ok())
            .collect()
    }
}

fn ingest_pcap(
    path: &Path,
    case: &mut Case,
    tracker: &mut SessionTracker,
    state: &mut DecodeState,
    output_dir: &Path,
    defang: bool,
    keywords: &[KeywordPattern],
) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader =
        PcapReader::new(BufReader::new(file)).map_err(|e| anyhow!("pcap header: {e}"))?;

    let mut frame: u64 = 0;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| anyhow!("pcap packet: {e}"))?;
        frame += 1;
        let ts = pkt.timestamp.as_secs_f64();
        decode::process_frame(
            case,
            tracker,
            state,
            output_dir,
            defang,
            keywords,
            frame,
            ts,
            &pkt.data,
        )?;
    }
    Ok(())
}

fn ingest_pcapng(
    path: &Path,
    case: &mut Case,
    tracker: &mut SessionTracker,
    state: &mut DecodeState,
    output_dir: &Path,
    defang: bool,
    keywords: &[KeywordPattern],
) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader =
        PcapNgReader::new(BufReader::new(file)).map_err(|e| anyhow!("pcapng header: {e}"))?;

    let mut frame: u64 = 0;
    while let Some(block) = reader.next_block() {
        let block = block.map_err(|e| anyhow!("pcapng block: {e}"))?;
        if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block {
            frame += 1;
            let ts = epb.timestamp.as_secs_f64();
            decode::process_frame(
                case,
                tracker,
                state,
                output_dir,
                defang,
                keywords,
                frame,
                ts,
                &epb.data,
            )?;
        } else if let pcap_file::pcapng::Block::SimplePacket(spb) = block {
            frame += 1;
            decode::process_frame(
                case,
                tracker,
                state,
                output_dir,
                defang,
                keywords,
                frame,
                0.0,
                &spb.data,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn match_keywords(
    case: &mut Case,
    keywords: &[KeywordPattern],
    payload: &[u8],
    frame: u64,
    session: &str,
) {
    for kw in keywords {
        match kw {
            KeywordPattern::Text(t) => {
                if memmem_find(payload, t.as_bytes()) {
                    let ctx = context_around(payload, t.as_bytes());
                    case.keywords.push(crate::case::KeywordHit {
                        keyword: t.clone(),
                        context: ctx,
                        frame,
                        session: session.to_string(),
                    });
                }
            }
            KeywordPattern::Hex(label, bytes) if !bytes.is_empty() => {
                if memmem_find(payload, bytes) {
                    let ctx = context_around(payload, bytes);
                    case.keywords.push(crate::case::KeywordHit {
                        keyword: label.clone(),
                        context: ctx,
                        frame,
                        session: session.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
}

fn memmem_find(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn context_around(hay: &[u8], needle: &[u8]) -> String {
    if let Some(pos) = hay.windows(needle.len()).position(|w| w == needle) {
        let start = pos.saturating_sub(24);
        let end = (pos + needle.len() + 24).min(hay.len());
        String::from_utf8_lossy(&hay[start..end])
            .chars()
            .map(|c| if c.is_control() { '.' } else { c })
            .collect()
    } else {
        String::new()
    }
}
