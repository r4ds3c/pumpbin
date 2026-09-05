//! TFTP RRQ/WRQ + DATA block reassembly.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;

use crate::case::{Case, Parameter};
use crate::extract::{self, SaveOpts};

#[derive(Default)]
pub struct TftpState {
    /// (client, server, transfer_id) -> (filename, mode, blocks)
    transfers: HashMap<(IpAddr, IpAddr, u16), TftpXfer>,
}

struct TftpXfer {
    filename: String,
    mode: String,
    blocks: HashMap<u16, Vec<u8>>,
    last_block: Option<u16>,
}

impl TftpState {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn handle(
    case: &mut Case,
    state: &mut TftpState,
    output_dir: &Path,
    defang: bool,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
) -> Result<()> {
    if payload.len() < 2 {
        return Ok(());
    }
    if !(sport == 69 || dport == 69 || state.transfers.keys().any(|(a, b, _)| (*a == src && *b == dst) || (*a == dst && *b == src))) {
        // still accept if opcode looks like TFTP
        let op = u16::from_be_bytes([payload[0], payload[1]]);
        if op > 5 {
            return Ok(());
        }
    }

    let opcode = u16::from_be_bytes([payload[0], payload[1]]);
    match opcode {
        1 | 2 => {
            // RRQ / WRQ: filename\0mode\0
            let rest = &payload[2..];
            let parts: Vec<&[u8]> = rest.split(|&b| b == 0).filter(|p| !p.is_empty()).collect();
            if parts.len() >= 2 {
                let filename = String::from_utf8_lossy(parts[0]).into_owned();
                let mode = String::from_utf8_lossy(parts[1]).into_owned();
                case.parameters.push(Parameter {
                    name: if opcode == 1 { "RRQ" } else { "WRQ" }.into(),
                    value: filename.clone(),
                    source: "TFTP".into(),
                    host: Some(dst),
                });
                let key = (src, dst, sport);
                state.transfers.insert(
                    key,
                    TftpXfer {
                        filename,
                        mode,
                        blocks: HashMap::new(),
                        last_block: None,
                    },
                );
            }
        }
        3 => {
            // DATA: block#(2) + data
            if payload.len() < 4 {
                return Ok(());
            }
            let block = u16::from_be_bytes([payload[2], payload[3]]);
            let data = payload[4..].to_vec();
            let is_last = data.len() < 512;
            // Match transfer by either direction
            let key = state
                .transfers
                .keys()
                .find(|(a, b, tid)| {
                    (*a == src && *b == dst && *tid == dport)
                        || (*a == dst && *b == src && *tid == sport)
                        || (*a == src && *b == dst)
                        || (*a == dst && *b == src)
                })
                .cloned();
            if let Some(key) = key {
                if let Some(xfer) = state.transfers.get_mut(&key) {
                    xfer.blocks.insert(block, data);
                    if is_last {
                        xfer.last_block = Some(block);
                        finalize(case, output_dir, defang, xfer, src, dst)?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn finalize(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    xfer: &TftpXfer,
    src: IpAddr,
    dst: IpAddr,
) -> Result<()> {
    let Some(last) = xfer.last_block else {
        return Ok(());
    };
    let mut out = Vec::new();
    for i in 1..=last {
        if let Some(b) = xfer.blocks.get(&i) {
            out.extend_from_slice(b);
        } else {
            return Ok(()); // incomplete
        }
    }
    let name = extract::sanitize_filename(&xfer.filename);
    extract::save_extracted(
        case,
        &name,
        out,
        SaveOpts {
            output_dir,
            defang,
            protocol: "TFTP",
            source_host: Some(src),
            dest_host: Some(dst),
            content_type: Some(format!("tftp/{}", xfer.mode)),
        },
    )
}
