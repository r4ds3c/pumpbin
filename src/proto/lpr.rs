//! LPR/LPD (TCP 515) control file / data file name extraction.

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
    if !(sport == 515 || dport == 515 || payload.first() == Some(&0x02) || payload.first() == Some(&0x03))
    {
        return Ok(());
    }
    // Receive a printer job: \x02 queue\n
    // Receive control file: \x02 count name\n <data>
    // Receive data file: \x03 count name\n <data>
    if payload.is_empty() {
        return Ok(());
    }
    let cmd = payload[0];
    if matches!(cmd, 0x02 | 0x03) {
        if let Some(nl) = payload.iter().position(|&b| b == b'\n') {
            let header = String::from_utf8_lossy(&payload[1..nl]);
            let parts: Vec<_> = header.split_whitespace().collect();
            if parts.len() >= 2 {
                let count: usize = parts[0].parse().unwrap_or(0);
                let name = parts[1];
                case.parameters.push(Parameter {
                    name: if cmd == 0x02 {
                        "control_file"
                    } else {
                        "data_file"
                    }
                    .into(),
                    value: name.to_string(),
                    source: "LPR".into(),
                    host: Some(dst),
                });
                let data_start = nl + 1;
                if count > 0 && data_start < payload.len() {
                    let end = (data_start + count).min(payload.len());
                    let body = payload[data_start..end].to_vec();
                    if cmd == 0x03 && !body.is_empty() {
                        extract::save_extracted(
                            case,
                            &extract::sanitize_filename(name),
                            body,
                            SaveOpts {
                                output_dir,
                                defang,
                                protocol: "LPR",
                                source_host: Some(src),
                                dest_host: Some(dst),
                                content_type: None,
                            },
                        )?;
                    }
                }
            } else if !parts.is_empty() {
                case.parameters.push(Parameter {
                    name: "queue".into(),
                    value: parts[0].to_string(),
                    source: "LPR".into(),
                    host: Some(dst),
                });
            }
        }
    }
    Ok(())
}
