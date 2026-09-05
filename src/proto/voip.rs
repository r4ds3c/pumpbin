//! SIP + RTP VoIP extraction and G.711 → WAV (playback via OS open).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::case::{Case, VoipCall};
use crate::extract;

#[derive(Default)]
pub struct VoipState {
    /// call-id → metadata
    calls: HashMap<String, CallMeta>,
    /// (src_ip, sport, dst_ip, dport) → RTP buffer keyed by sequence
    rtp: HashMap<RtpKey, RtpBuf>,
}

#[derive(Debug, Clone)]
struct CallMeta {
    from: String,
    to: String,
    /// negotiated media endpoints from SDP
    media: Vec<(IpAddr, u16)>,
    codec: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RtpKey {
    a: IpAddr,
    ap: u16,
    b: IpAddr,
    bp: u16,
}

#[derive(Default)]
struct RtpBuf {
    /// seq → payload (G.711)
    packets: HashMap<u16, Vec<u8>>,
    payload_type: u8,
    ssrc: u32,
}

impl VoipState {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn handle_udp(
    case: &mut Case,
    state: &mut VoipState,
    output_dir: &Path,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
) -> Result<()> {
    if looks_like_sip(payload) {
        handle_sip(case, state, payload, src, dst);
        return Ok(());
    }
    if looks_like_rtp(payload) {
        handle_rtp(case, state, output_dir, payload, src, dst, sport, dport)?;
    }
    Ok(())
}

fn looks_like_sip(p: &[u8]) -> bool {
    p.starts_with(b"INVITE ")
        || p.starts_with(b"SIP/2.0")
        || p.starts_with(b"ACK ")
        || p.starts_with(b"BYE ")
        || p.starts_with(b"OPTIONS ")
        || p.starts_with(b"REGISTER ")
}

fn looks_like_rtp(p: &[u8]) -> bool {
    if p.len() < 12 {
        return false;
    }
    let v = p[0] >> 6;
    let pt = p[1] & 0x7f;
    v == 2 && (pt == 0 || pt == 8 || pt == 9) // PCMU, PCMA, G.722
}

fn handle_sip(case: &mut Case, state: &mut VoipState, payload: &[u8], src: IpAddr, _dst: IpAddr) {
    let text = String::from_utf8_lossy(payload);
    let mut call_id = String::new();
    let mut from = String::new();
    let mut to = String::new();
    let mut in_sdp = false;
    let mut media_ip: Option<IpAddr> = None;
    let mut media_port: Option<u16> = None;
    let mut codec = "G.711".to_string();

    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("call-id:") {
            call_id = line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if lower.starts_with("from:") {
            from = extract_sip_uri(line);
        } else if lower.starts_with("to:") {
            to = extract_sip_uri(line);
        } else if line.trim().is_empty() {
            in_sdp = true;
        } else if in_sdp {
            if lower.starts_with("c=in ip4 ") {
                if let Some(ip) = line.split_whitespace().nth(2).and_then(|s| s.parse().ok()) {
                    media_ip = Some(ip);
                }
            } else if lower.starts_with("m=audio ") {
                if let Some(p) = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
                    media_port = Some(p);
                }
                if lower.contains("pcmu") {
                    codec = "G.711 μ-law".into();
                } else if lower.contains("pcma") {
                    codec = "G.711 A-law".into();
                } else if lower.contains("g722") {
                    codec = "G.722".into();
                }
            }
        }
    }

    if call_id.is_empty() {
        return;
    }
    let entry = state.calls.entry(call_id.clone()).or_insert_with(|| CallMeta {
        from: from.clone(),
        to: to.clone(),
        media: Vec::new(),
        codec: codec.clone(),
    });
    if !from.is_empty() {
        entry.from = from;
    }
    if !to.is_empty() {
        entry.to = to;
    }
    entry.codec = codec.clone();
    if let (Some(ip), Some(port)) = (media_ip, media_port) {
        if !entry.media.iter().any(|(i, p)| *i == ip && *p == port) {
            entry.media.push((ip, port));
        }
        // also associate with SIP source as possible RTP peer
        let _ = src;
    }

    if !case.voip_calls.iter().any(|c| c.call_id == call_id) {
        case.voip_calls.push(VoipCall {
            call_id: call_id.clone(),
            from: entry.from.clone(),
            to: entry.to.clone(),
            codec: entry.codec.clone(),
            audio_path: None,
        });
    }
}

fn extract_sip_uri(line: &str) -> String {
    if let Some(start) = line.find('<') {
        if let Some(end) = line[start..].find('>') {
            return line[start + 1..start + end].to_string();
        }
    }
    line.split_once(':')
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

fn handle_rtp(
    case: &mut Case,
    state: &mut VoipState,
    output_dir: &Path,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
) -> Result<()> {
    let pt = payload[1] & 0x7f;
    let seq = u16::from_be_bytes([payload[2], payload[3]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let cc = (payload[0] & 0x0f) as usize;
    let header_len = 12 + cc * 4;
    if payload.len() <= header_len {
        return Ok(());
    }
    let body = payload[header_len..].to_vec();

    let key = {
        let forward = (src, sport) <= (dst, dport);
        if forward {
            RtpKey {
                a: src,
                ap: sport,
                b: dst,
                bp: dport,
            }
        } else {
            RtpKey {
                a: dst,
                ap: dport,
                b: src,
                bp: sport,
            }
        }
    };

    let buf = state.rtp.entry(key.clone()).or_default();
    buf.payload_type = pt;
    buf.ssrc = ssrc;
    buf.packets.insert(seq, body);

    // Flush when we have enough samples (~0.5s at 8kHz = 4000 bytes)
    let total: usize = buf.packets.values().map(|v| v.len()).sum();
    if total >= 4000 || buf.packets.len() >= 100 {
        flush_rtp(case, state, output_dir, &key)?;
    }
    Ok(())
}

fn flush_rtp(
    case: &mut Case,
    state: &mut VoipState,
    output_dir: &Path,
    key: &RtpKey,
) -> Result<()> {
    let Some(buf) = state.rtp.remove(key) else {
        return Ok(());
    };
    if buf.packets.is_empty() {
        return Ok(());
    }
    let mut seqs: Vec<_> = buf.packets.keys().copied().collect();
    seqs.sort_unstable();
    let mut ulaw = Vec::new();
    for s in seqs {
        if let Some(p) = buf.packets.get(&s) {
            ulaw.extend_from_slice(p);
        }
    }
    if ulaw.is_empty() {
        return Ok(());
    }

    if buf.payload_type == 9 {
        let raw_path = extract::unique_path(output_dir, &format!("voip_{:08x}.g722", buf.ssrc));
        std::fs::write(&raw_path, &ulaw)?;
        push_call(case, key, "G.722", Some(raw_path));
        return Ok(());
    }

    let (pcm, codec) = match buf.payload_type {
        0 => (ulaw_to_pcm(&ulaw), "G.711 μ-law"),
        8 => (alaw_to_pcm(&ulaw), "G.711 A-law"),
        _ => return Ok(()),
    };

    let name = format!("voip_{:08x}.wav", buf.ssrc);
    let path = extract::unique_path(output_dir, &name);
    write_wav_pcm16(&path, &pcm, 8000)?;
    push_call(case, key, codec, Some(path));
    Ok(())
}

fn push_call(case: &mut Case, key: &RtpKey, codec: &str, path: Option<PathBuf>) {
    let id = format!("{}:{}-{}:{}", key.a, key.ap, key.b, key.bp);
    if let Some(existing) = case.voip_calls.iter_mut().find(|c| c.audio_path.is_none()) {
        existing.audio_path = path;
        existing.codec = codec.into();
        if existing.call_id.is_empty() {
            existing.call_id = id;
        }
        return;
    }
    if !case.voip_calls.iter().any(|c| c.call_id == id) {
        case.voip_calls.push(VoipCall {
            call_id: id,
            from: key.a.to_string(),
            to: key.b.to_string(),
            codec: codec.into(),
            audio_path: path,
        });
    } else if let Some(c) = case.voip_calls.iter_mut().find(|c| c.call_id == id) {
        c.audio_path = path.or_else(|| c.audio_path.clone());
        c.codec = codec.into();
    }
}

/// Finalize remaining RTP buffers (call at end of ingest).
pub fn finalize(case: &mut Case, state: &mut VoipState, output_dir: &Path) -> Result<()> {
    let keys: Vec<_> = state.rtp.keys().cloned().collect();
    for key in keys {
        flush_rtp(case, state, output_dir, &key)?;
    }
    Ok(())
}

fn write_wav_pcm16(path: &Path, pcm: &[i16], sample_rate: u32) -> Result<()> {
    let data_len = (pcm.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_len as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&(sample_rate * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for s in pcm {
        out.extend_from_slice(&s.to_le_bytes());
    }
    std::fs::write(path, out)?;
    Ok(())
}

fn ulaw_to_pcm(data: &[u8]) -> Vec<i16> {
    data.iter().map(|&u| ulaw_decode(u)).collect()
}

fn alaw_to_pcm(data: &[u8]) -> Vec<i16> {
    data.iter().map(|&a| alaw_decode(a)).collect()
}

fn ulaw_decode(mut u: u8) -> i16 {
    u = !u;
    let sign = u & 0x80;
    let exponent = (u >> 4) & 0x07;
    let mantissa = u & 0x0f;
    let mut sample = ((mantissa as i32) << 3) + 0x84;
    sample <<= exponent as i32;
    sample -= 0x84;
    if sign != 0 {
        (-sample) as i16
    } else {
        sample as i16
    }
}

fn alaw_decode(mut a: u8) -> i16 {
    a ^= 0x55;
    let sign = a & 0x80;
    let exponent = (a >> 4) & 0x07;
    let mantissa = a & 0x0f;
    let mut sample = ((mantissa as i32) << 4) + 8;
    if exponent != 0 {
        sample += 0x100;
    }
    if exponent > 1 {
        sample <<= exponent as i32 - 1;
    }
    if sign != 0 {
        sample = -sample;
    }
    sample as i16
}
