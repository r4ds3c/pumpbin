//! HTTP/2 preface detection and DATA frame payload extraction (no full HPACK).

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;

use crate::case::{Case, Parameter};
use crate::extract::{self, SaveOpts};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub fn handle_segment(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
) -> Result<()> {
    if payload.starts_with(PREFACE) {
        case.parameters.push(Parameter {
            name: "preface".into(),
            value: "PRI * HTTP/2.0".into(),
            source: "HTTP/2".into(),
            host: Some(dst),
        });
        parse_frames(case, output_dir, defang, &payload[PREFACE.len()..], src, dst)?;
        return Ok(());
    }
    // Frames without preface (mid-stream)
    if payload.len() >= 9 && looks_like_frame(payload) {
        parse_frames(case, output_dir, defang, payload, src, dst)?;
    }
    Ok(())
}

fn looks_like_frame(p: &[u8]) -> bool {
    let len = ((p[0] as usize) << 16) | ((p[1] as usize) << 8) | p[2] as usize;
    let typ = p[3];
    len < 16_384 && typ <= 0x09 && 9 + len <= p.len()
}

fn parse_frames(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    mut data: &[u8],
    src: IpAddr,
    dst: IpAddr,
) -> Result<()> {
    while data.len() >= 9 {
        let len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
        let typ = data[3];
        let flags = data[4];
        let stream_id =
            u32::from_be_bytes([data[5] & 0x7f, data[6], data[7], data[8]]);
        if 9 + len > data.len() {
            break;
        }
        let payload = &data[9..9 + len];
        // DATA = 0x0
        if typ == 0x0 && !payload.is_empty() && stream_id != 0 {
            let pad = if flags & 0x08 != 0 {
                *payload.first().unwrap_or(&0) as usize
            } else {
                0
            };
            let body = if pad > 0 && payload.len() > 1 + pad {
                &payload[1..payload.len() - pad]
            } else {
                payload
            };
            if body.len() >= 16 {
                let name = format!("http2_stream_{stream_id}_{}.bin", extract::hex_sha256(body).chars().take(8).collect::<String>());
                extract::save_extracted(
                    case,
                    &name,
                    body.to_vec(),
                    SaveOpts {
                        output_dir,
                        defang,
                        protocol: "HTTP/2",
                        source_host: Some(src),
                        dest_host: Some(dst),
                        content_type: None,
                    },
                )?;
            }
        }
        data = &data[9 + len..];
    }
    Ok(())
}

pub fn looks_like_http2(payload: &[u8]) -> bool {
    payload.starts_with(PREFACE) || (payload.len() >= 9 && looks_like_frame(payload) && payload[3] <= 0x09)
}
