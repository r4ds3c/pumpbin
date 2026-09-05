//! SMB/SMB2 detection, path extraction, and SMB2 READ response file carve.

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;

use crate::case::{Case, Parameter};
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
    if !(sport == 445 || dport == 445 || sport == 139 || dport == 139) && !looks_smb(payload) {
        return Ok(());
    }

    if payload.starts_with(b"\xffSMB") {
        case.parameters.push(Parameter {
            name: "dialect".into(),
            value: "SMB1".into(),
            source: "SMB".into(),
            host: Some(dst),
        });
        extract_utf16_paths(case, payload, dst, "SMB1");
        return Ok(());
    }

    let smb = if payload.len() >= 8 && &payload[4..8] == b"\xfeSMB" {
        &payload[4..]
    } else if payload.starts_with(b"\xfeSMB") {
        payload
    } else {
        return Ok(());
    };

    case.parameters.push(Parameter {
        name: "dialect".into(),
        value: "SMB2+".into(),
        source: "SMB2".into(),
        host: Some(dst),
    });

    if smb.len() < 64 {
        return Ok(());
    }
    let cmd = u16::from_le_bytes([smb[12], smb[13]]);
    let flags = u32::from_le_bytes([smb[16], smb[17], smb[18], smb[19]]);
    let is_response = flags & 0x0000_0001 != 0;

    if cmd == 5 {
        // CREATE
        extract_utf16_paths(case, smb, dst, "SMB2 Create");
    }

    // SMB2 READ response (cmd 8) carries file bytes
    if cmd == 8 && is_response && smb.len() >= 64 + 16 {
        let structure_size = u16::from_le_bytes([smb[64], smb[65]]);
        if structure_size >= 17 {
            let data_offset = smb[66] as usize; // from start of SMB2 header
            let data_len = u32::from_le_bytes([smb[68], smb[69], smb[70], smb[71]]) as usize;
            let start = data_offset;
            if start > 0 && start + data_len <= smb.len() && data_len > 0 && data_len < 16_000_000 {
                let body = smb[start..start + data_len].to_vec();
                let name = format!(
                    "smb2_read_{}_{}.bin",
                    extract::hex_sha256(&body).chars().take(8).collect::<String>(),
                    data_len
                );
                extract::save_extracted(
                    case,
                    &name,
                    body,
                    SaveOpts {
                        output_dir,
                        defang,
                        protocol: "SMB2",
                        source_host: Some(src),
                        dest_host: Some(dst),
                        content_type: None,
                    },
                )?;
            }
        }
    }

    extract_utf16_paths(case, payload, dst, "SMB2");
    Ok(())
}

fn looks_smb(p: &[u8]) -> bool {
    p.starts_with(b"\xffSMB")
        || p.starts_with(b"\xfeSMB")
        || (p.len() >= 8 && &p[4..8] == b"\xfeSMB")
}

fn extract_utf16_paths(case: &mut Case, data: &[u8], host: IpAddr, source: &str) {
    let mut i = 0;
    while i + 1 < data.len() {
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
