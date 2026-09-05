//! Minimal SMB/SMB2 detection and Create/filename parameter extraction.

use std::net::IpAddr;

use crate::case::{Case, Parameter};

pub fn handle_segment(case: &mut Case, payload: &[u8], _src: IpAddr, dst: IpAddr, sport: u16, dport: u16) {
    if !(sport == 445 || dport == 445 || sport == 139 || dport == 139) && !looks_smb(payload) {
        return;
    }

    if payload.starts_with(b"\xffSMB") {
        case.parameters.push(Parameter {
            name: "dialect".into(),
            value: "SMB1".into(),
            source: "SMB".into(),
            host: Some(dst),
        });
        // SMB1 Path in some commands — best-effort UTF-16LE scan for \\ paths
        extract_utf16_paths(case, payload, dst, "SMB1");
        return;
    }

    if payload.len() >= 8 && &payload[4..8] == b"\xfeSMB" {
        case.parameters.push(Parameter {
            name: "dialect".into(),
            value: "SMB2+".into(),
            source: "SMB2".into(),
            host: Some(dst),
        });
        // SMB2 header is 64 bytes starting at offset 0 of NetBIOS-less or after 4-byte length
        let smb = if payload.len() > 68 && &payload[4..8] == b"\xfeSMB" {
            &payload[4..]
        } else {
            payload
        };
        if smb.len() >= 64 {
            let cmd = u16::from_le_bytes([smb[12], smb[13]]);
            // 5 = CREATE
            if cmd == 5 {
                extract_utf16_paths(case, smb, dst, "SMB2 Create");
            }
        }
        extract_utf16_paths(case, payload, dst, "SMB2");
    }
}

fn looks_smb(p: &[u8]) -> bool {
    p.starts_with(b"\xffSMB") || (p.len() >= 8 && &p[4..8] == b"\xfeSMB")
}

fn extract_utf16_paths(case: &mut Case, data: &[u8], host: IpAddr, source: &str) {
    // Scan for UTF-16LE sequences that look like paths (e.g. \x00.\x00e\x00x\x00e)
    let mut i = 0;
    while i + 1 < data.len() {
        // look for '\' = 5c 00
        if data[i] == b'\\' && data[i + 1] == 0 {
            let mut chars = Vec::new();
            let mut j = i;
            while j + 1 < data.len() {
                let lo = data[j];
                let hi = data[j + 1];
                if hi != 0 || lo == 0 {
                    break;
                }
                if lo.is_ascii_graphic() || lo == b' ' || lo == b'\\' {
                    chars.push(lo as char);
                    j += 2;
                } else {
                    break;
                }
            }
            let s: String = chars.into_iter().collect();
            if s.len() >= 4 && s.contains('\\') {
                if !case
                    .parameters
                    .iter()
                    .any(|p| p.source.starts_with("SMB") && p.value == s)
                {
                    case.parameters.push(Parameter {
                        name: "path".into(),
                        value: s,
                        source: source.into(),
                        host: Some(host),
                    });
                }
            }
            i = j.max(i + 2);
        } else {
            i += 1;
        }
    }
}
