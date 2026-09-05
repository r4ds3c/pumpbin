//! Chat / RAT / ICS extractors: IRC, OSCAR (AIM), IEC-104, njRAT hints.

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;

use crate::case::{Case, Credential, MessageArtifact, Parameter};
use crate::extract::{self, SaveOpts};

pub fn handle_segment(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
) -> Result<()> {
    handle_irc(case, payload, src, dst);
    handle_oscar(case, payload, src, dst);
    handle_iec104(case, output_dir, defang, payload, src, dst, sport, dport)?;
    handle_njrat(case, payload, src, dst);
    Ok(())
}

fn handle_irc(case: &mut Case, payload: &[u8], src: IpAddr, dst: IpAddr) {
    let text = String::from_utf8_lossy(payload);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("PRIVMSG ") || t.starts_with("NOTICE ") {
            let mut parts = t.splitn(3, ' ');
            let cmd = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("").to_string();
            let body = parts.next().unwrap_or("").trim_start_matches(':');
            case.messages.push(MessageArtifact {
                protocol: "IRC".into(),
                subject: format!("{cmd} {target}"),
                from: src.to_string(),
                to: target,
                body_preview: body.chars().take(400).collect(),
            });
        } else if let Some(rest) = t.strip_prefix("NICK ") {
            case.parameters.push(Parameter {
                name: "NICK".into(),
                value: rest.to_string(),
                source: "IRC".into(),
                host: Some(dst),
            });
        } else if t.starts_with("JOIN ") || t.starts_with("PART ") {
            case.parameters.push(Parameter {
                name: t.split_whitespace().next().unwrap_or("IRC").into(),
                value: t.to_string(),
                source: "IRC".into(),
                host: Some(dst),
            });
        }
    }
}

/// OSCAR/AIM FLAP frames start with 0x2A.
fn handle_oscar(case: &mut Case, payload: &[u8], src: IpAddr, dst: IpAddr) {
    if payload.first() != Some(&0x2A) || payload.len() < 6 {
        return;
    }
    let channel = payload[1];
    let seq = u16::from_be_bytes([payload[2], payload[3]]);
    let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    case.parameters.push(Parameter {
        name: "FLAP".into(),
        value: format!("ch={channel} seq={seq} len={len}"),
        source: "OSCAR".into(),
        host: Some(dst),
    });
    if channel == 0x02 && payload.len() > 6 {
        let body = &payload[6..payload.len().min(6 + len)];
        let preview = String::from_utf8_lossy(body);
        if preview.chars().any(|c| c.is_ascii_alphanumeric()) {
            case.messages.push(MessageArtifact {
                protocol: "OSCAR".into(),
                subject: format!("FLAP ch={channel}"),
                from: src.to_string(),
                to: dst.to_string(),
                body_preview: preview.chars().take(200).collect(),
            });
        }
    }
}

/// IEC 60870-5-104: APDUs start with 0x68.
fn handle_iec104(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
) -> Result<()> {
    if !(sport == 2404 || dport == 2404 || payload.first() == Some(&0x68)) {
        return Ok(());
    }
    let mut off = 0usize;
    while off + 2 <= payload.len() && payload[off] == 0x68 {
        let apdu_len = payload[off + 1] as usize;
        if off + 2 + apdu_len > payload.len() {
            break;
        }
        let apdu = &payload[off + 2..off + 2 + apdu_len];
        case.parameters.push(Parameter {
            name: "APDU".into(),
            value: format!("len={apdu_len} ctrl={:02x?}", &apdu[..apdu.len().min(4)]),
            source: "IEC-104".into(),
            host: Some(dst),
        });
        if apdu_len > 4 {
            let asdu = &apdu[4..];
            if asdu.len() >= 8 {
                extract::save_extracted(
                    case,
                    &format!("iec104_{}_{}.bin", src, off),
                    asdu.to_vec(),
                    SaveOpts {
                        output_dir,
                        defang,
                        protocol: "IEC-104",
                        source_host: Some(src),
                        dest_host: Some(dst),
                        content_type: Some("application/iec104".into()),
                    },
                )?;
            }
        }
        off += 2 + apdu_len;
    }
    Ok(())
}

/// njRAT / Bladabindi cleartext markers commonly seen in C2.
fn handle_njrat(case: &mut Case, payload: &[u8], _src: IpAddr, dst: IpAddr) {
    let text = String::from_utf8_lossy(payload);
    let markers = ["njRAT", "|'|'|", "ll|'|'|", "inf|'|'|", "rs|'|'|", "kl|'|'|"];
    if !markers.iter().any(|m| text.contains(m)) {
        return;
    }
    case.parameters.push(Parameter {
        name: "family".into(),
        value: "njRAT".into(),
        source: "njRAT".into(),
        host: Some(dst),
    });
    // Split on |'|'|
    for part in text.split("|'|'|") {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if p.contains('@') || p.contains(':') {
            case.credentials.push(Credential {
                protocol: "njRAT".into(),
                username: p.to_string(),
                secret: String::new(),
                host: Some(dst),
                details: "field".into(),
            });
        }
        case.messages.push(MessageArtifact {
            protocol: "njRAT".into(),
            subject: "C2 field".into(),
            from: String::new(),
            to: dst.to_string(),
            body_preview: p.chars().take(200).collect(),
        });
    }
}
