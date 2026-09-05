//! Packet carver: recover Ethernet/IP frames from unstructured blobs / memory dumps.

use std::path::Path;

use anyhow::{Context, Result};

use crate::capture::{self, IngestOptions};
use crate::case::Case;
use crate::decode::{self, DecodeState};
use crate::reassembly::SessionTracker;

/// Minimum Ethernet frame size we will accept when carving.
const MIN_FRAME: usize = 60;
/// Cap carved frame size (snaplen-like).
const MAX_FRAME: usize = 65535;

/// Carve frames from a raw dump and ingest into a case.
pub fn carve_file(path: &Path, output_dir: &Path, opts: &IngestOptions) -> Result<Case> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    carve_bytes(&data, Some(path), output_dir, opts)
}

pub fn carve_bytes(
    data: &[u8],
    source: Option<&Path>,
    output_dir: &Path,
    opts: &IngestOptions,
) -> Result<Case> {
    let mut case = Case {
        source_path: source.map(|p| p.to_path_buf()),
        ..Case::default()
    };
    std::fs::create_dir_all(output_dir)?;
    let mut tracker = SessionTracker::new();
    let mut state = DecodeState::new();
    let keywords = capture::parse_keywords_pub(&opts.keywords);

    let frames = carve_frames(data);
    for (i, frame) in frames.iter().enumerate() {
        decode::process_frame(
            &mut case,
            &mut tracker,
            &mut state,
            output_dir,
            opts.defang_executables,
            &keywords,
            (i as u64) + 1,
            0.0,
            frame,
        )?;
    }

    case.anomalies.push(crate::case::Anomaly {
        kind: "carver".into(),
        detail: format!("carved {} candidate frames from {} bytes", frames.len(), data.len()),
        frame: 0,
    });
    case.sessions = tracker.into_sessions();
    decode::finalize(&mut case, &mut state, output_dir)?;
    Ok(case)
}

/// Scan for Ethernet II frames (unicast/multicast dest, EtherType IPv4/IPv6/ARP/VLAN).
pub fn carve_frames(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + MIN_FRAME <= data.len() {
        if let Some(frame_len) = look_like_ethernet(&data[i..]) {
            let end = (i + frame_len).min(data.len());
            out.push(data[i..end].to_vec());
            i = end;
            continue;
        }
        // Also try raw IPv4/IPv6 at this offset (wrap as Ethernet)
        if let Some(ip_len) = look_like_ipv4(&data[i..]) {
            let end = (i + ip_len).min(data.len());
            let mut eth = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
            eth.extend_from_slice(&data[i..end]);
            out.push(eth);
            i = end;
            continue;
        }
        if let Some(ip_len) = look_like_ipv6(&data[i..]) {
            let end = (i + ip_len).min(data.len());
            let mut eth = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x86, 0xdd];
            eth.extend_from_slice(&data[i..end]);
            out.push(eth);
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

fn look_like_ethernet(data: &[u8]) -> Option<usize> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let (payload_hint, skip) = match ethertype {
        0x0800 => (look_like_ipv4(&data[14..])?, 14),
        0x86dd => (look_like_ipv6(&data[14..])?, 14),
        0x0806 => (28usize.min(data.len().saturating_sub(14)), 14), // ARP
        0x8100 | 0x88a8 if data.len() >= 18 => {
            let inner = u16::from_be_bytes([data[16], data[17]]);
            let plen = match inner {
                0x0800 => look_like_ipv4(&data[18..])?,
                0x86dd => look_like_ipv6(&data[18..])?,
                _ => return None,
            };
            return Some((18 + plen).min(MAX_FRAME));
        }
        _ => return None,
    };
    Some((skip + payload_hint).clamp(MIN_FRAME, MAX_FRAME))
}

fn look_like_ipv4(data: &[u8]) -> Option<usize> {
    if data.len() < 20 {
        return None;
    }
    let ver_ihl = data[0];
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total < ihl || total > MAX_FRAME {
        return None;
    }
    // Basic sanity: protocol field
    let proto = data[9];
    if !matches!(proto, 1 | 6 | 17 | 47 | 50 | 51) {
        // allow common; still accept if total looks ok
        if total < 20 {
            return None;
        }
    }
    Some(total)
}

fn look_like_ipv6(data: &[u8]) -> Option<usize> {
    if data.len() < 40 {
        return None;
    }
    if data[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let total = 40 + payload_len;
    if total > MAX_FRAME || total < 40 {
        return None;
    }
    Some(total)
}
