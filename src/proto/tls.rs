//! TLS handshake metadata: SNI, JA3/JA3S/JA4, X.509 cert extract (no app-data decrypt).

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use md5::{Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};
use x509_parser::prelude::*;

use crate::case::{Case, TlsHandshake};
use crate::extract::{self, SaveOpts};

const TLS_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const CERTIFICATE: u8 = 11;

pub fn handle_segment(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    frame: u64,
) -> Result<()> {
    if payload.len() < 5 || payload[0] != TLS_HANDSHAKE {
        return Ok(());
    }
    // Walk TLS records in the TCP segment
    let mut off = 0usize;
    while off + 5 <= payload.len() {
        if payload[off] != TLS_HANDSHAKE {
            break;
        }
        let rec_len = u16::from_be_bytes([payload[off + 3], payload[off + 4]]) as usize;
        let start = off + 5;
        let end = (start + rec_len).min(payload.len());
        if start >= end {
            break;
        }
        parse_handshake_records(
            case,
            output_dir,
            defang,
            &payload[start..end],
            src,
            dst,
            sport,
            dport,
            frame,
        )?;
        off = end;
    }
    Ok(())
}

fn parse_handshake_records(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    data: &[u8],
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    frame: u64,
) -> Result<()> {
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let msg_type = data[off];
        let len = ((data[off + 1] as usize) << 16)
            | ((data[off + 2] as usize) << 8)
            | data[off + 3] as usize;
        off += 4;
        if off + len > data.len() {
            break;
        }
        let body = &data[off..off + len];
        match msg_type {
            CLIENT_HELLO => {
                if let Some(info) = parse_client_hello(body) {
                    if let Some(ref sni) = info.sni {
                        let host = case.ensure_host(dst);
                        if !host.hostnames.contains(sni) {
                            host.hostnames.push(sni.clone());
                        }
                    }
                    case.tls_handshakes.push(TlsHandshake {
                        frame,
                        client: src,
                        server: dst,
                        client_port: sport,
                        server_port: dport,
                        sni: info.sni,
                        ja3: Some(info.ja3),
                        ja3s: None,
                        ja4: Some(info.ja4),
                        version: info.version_label,
                        role: "client".into(),
                    });
                }
            }
            SERVER_HELLO => {
                if let Some(info) = parse_server_hello(body) {
                    case.tls_handshakes.push(TlsHandshake {
                        frame,
                        client: dst,
                        server: src,
                        client_port: dport,
                        server_port: sport,
                        sni: None,
                        ja3: None,
                        ja3s: Some(info.ja3s),
                        ja4: None,
                        version: info.version_label,
                        role: "server".into(),
                    });
                }
            }
            CERTIFICATE => {
                extract_certs(case, output_dir, defang, body, src, dst)?;
            }
            _ => {}
        }
        off += len;
    }
    Ok(())
}

struct ClientHelloInfo {
    sni: Option<String>,
    ja3: String,
    ja4: String,
    version_label: Option<String>,
}

struct ServerHelloInfo {
    ja3s: String,
    version_label: Option<String>,
}

fn parse_client_hello(body: &[u8]) -> Option<ClientHelloInfo> {
    if body.len() < 38 {
        return None;
    }
    let version = u16::from_be_bytes([body[0], body[1]]);
    let mut off = 34; // version + random
    let sid_len = *body.get(off)? as usize;
    off += 1 + sid_len;
    if off + 2 > body.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + cs_len > body.len() {
        return None;
    }
    let mut ciphers = Vec::new();
    for i in (0..cs_len).step_by(2) {
        if i + 1 < cs_len {
            ciphers.push(u16::from_be_bytes([body[off + i], body[off + i + 1]]));
        }
    }
    off += cs_len;
    let comp_len = *body.get(off)? as usize;
    off += 1 + comp_len;
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();
    let mut alpn = None;
    let mut sig_algs = Vec::new();
    if off + 2 <= body.len() {
        let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_len).min(body.len());
        while off + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[off], body[off + 1]]);
            let elen = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
            off += 4;
            if off + elen > ext_end {
                break;
            }
            let edata = &body[off..off + elen];
            extensions.push(etype);
            match etype {
                0 => sni = parse_sni(edata),
                10 => curves = parse_u16_list(edata),
                11 => {
                    if !edata.is_empty() {
                        let n = edata[0] as usize;
                        point_formats.extend_from_slice(&edata[1..edata.len().min(1 + n)]);
                    }
                }
                16 => alpn = parse_alpn(edata),
                13 => sig_algs = parse_u16_list(edata),
                _ => {}
            }
            off += elen;
        }
    }

    let cipher_str = join_u16(&ciphers);
    let ext_str = join_u16(&extensions);
    let curve_str = join_u16(&curves);
    let pf_str = point_formats
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_raw = format!("{version},{cipher_str},{ext_str},{curve_str},{pf_str}");
    let ja3 = md5_hex(ja3_raw.as_bytes());

    let ja4 = compute_ja4(version, &ciphers, &extensions, sni.is_some(), alpn.as_deref(), &sig_algs);

    Some(ClientHelloInfo {
        sni,
        ja3,
        ja4,
        version_label: Some(tls_ver_label(version)),
    })
}

fn parse_server_hello(body: &[u8]) -> Option<ServerHelloInfo> {
    if body.len() < 38 {
        return None;
    }
    let version = u16::from_be_bytes([body[0], body[1]]);
    let mut off = 34;
    let sid_len = *body.get(off)? as usize;
    off += 1 + sid_len;
    if off + 3 > body.len() {
        return None;
    }
    let cipher = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 3; // cipher + compression
    let mut extensions = Vec::new();
    if off + 2 <= body.len() {
        let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_len).min(body.len());
        while off + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[off], body[off + 1]]);
            let elen = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
            off += 4;
            extensions.push(etype);
            off += elen;
            if off > ext_end {
                break;
            }
        }
    }
    let ja3s_raw = format!("{version},{cipher},{}", join_u16(&extensions));
    Some(ServerHelloInfo {
        ja3s: md5_hex(ja3s_raw.as_bytes()),
        version_label: Some(tls_ver_label(version)),
    })
}

fn extract_certs(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    body: &[u8],
    src: IpAddr,
    dst: IpAddr,
) -> Result<()> {
    if body.len() < 3 {
        return Ok(());
    }
    let list_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    let mut off = 3;
    let end = (3 + list_len).min(body.len());
    let mut idx = 0usize;
    while off + 3 <= end {
        let clen = ((body[off] as usize) << 16) | ((body[off + 1] as usize) << 8) | body[off + 2] as usize;
        off += 3;
        if off + clen > end {
            break;
        }
        let der = body[off..off + clen].to_vec();
        off += clen;
        let subject = X509Certificate::from_der(&der)
            .ok()
            .map(|(_, cert)| cert.subject().to_string())
            .unwrap_or_else(|| format!("cert_{idx}"));
        let name = extract::sanitize_filename(&format!("{subject}.cer"));
        extract::save_extracted(
            case,
            &name,
            der,
            SaveOpts {
                output_dir,
                defang,
                protocol: "TLS",
                source_host: Some(src),
                dest_host: Some(dst),
                content_type: Some("application/pkix-cert".into()),
            },
        )?;
        idx += 1;
    }
    Ok(())
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // list_len(2) type(1) name_len(2) name
    let mut off = 2;
    while off + 3 <= data.len() {
        let typ = data[off];
        let nlen = u16::from_be_bytes([data[off + 1], data[off + 2]]) as usize;
        off += 3;
        if typ == 0 && off + nlen <= data.len() {
            return Some(String::from_utf8_lossy(&data[off..off + nlen]).into_owned());
        }
        off += nlen;
    }
    None
}

fn parse_alpn(data: &[u8]) -> Option<String> {
    if data.len() < 3 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut off = 2;
    let end = (2 + list_len).min(data.len());
    if off < end {
        let n = data[off] as usize;
        off += 1;
        if off + n <= end {
            return Some(String::from_utf8_lossy(&data[off..off + n]).into_owned());
        }
    }
    None
}

fn parse_u16_list(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut out = Vec::new();
    let mut off = 2;
    let end = (2 + list_len).min(data.len());
    while off + 1 < end {
        out.push(u16::from_be_bytes([data[off], data[off + 1]]));
        off += 2;
    }
    out
}

fn join_u16(v: &[u16]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", Md5::digest(data))
}

fn sha256_12(data: &[u8]) -> String {
    format!("{:x}", <Sha256 as Sha2Digest>::digest(data))
        .chars()
        .take(12)
        .collect()
}

/// Simplified JA4 fingerprint (FoxIO-style layout; clean-room from public docs).
fn compute_ja4(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    has_sni: bool,
    alpn: Option<&str>,
    sig_algs: &[u16],
) -> String {
    let ver = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_f = if has_sni { "d" } else { "i" };
    let cipher_count = format!("{:02}", ciphers.len().min(99));
    let ext_count = format!("{:02}", extensions.len().min(99));
    let alpn_f = match alpn {
        Some(a) if a.len() >= 2 => format!("{}{}", &a[..1], &a[a.len() - 1..]),
        Some(a) if !a.is_empty() => format!("{a}{a}"),
        _ => "00".into(),
    };
    let a = format!("t{ver}{sni_f}{cipher_count}{ext_count}{alpn_f}");

    let mut sorted_ciphers = ciphers.to_vec();
    sorted_ciphers.sort_unstable();
    let b = sha256_12(
        sorted_ciphers
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<_>>()
            .join(",")
            .as_bytes(),
    );

    let mut sorted_ext = extensions
        .iter()
        .copied()
        .filter(|&e| e != 0 && e != 16) // exclude SNI and ALPN per JA4
        .collect::<Vec<_>>();
    sorted_ext.sort_unstable();
    let mut c_parts: Vec<String> = sorted_ext.iter().map(|e| format!("{e:04x}")).collect();
    if !sig_algs.is_empty() {
        c_parts.push("_".into());
        c_parts.extend(sig_algs.iter().map(|s| format!("{s:04x}")));
    }
    let c = sha256_12(c_parts.join(",").as_bytes());
    format!("{a}_{b}_{c}")
}

fn tls_ver_label(v: u16) -> String {
    match v {
        0x0304 => "TLS 1.3".into(),
        0x0303 => "TLS 1.2".into(),
        0x0302 => "TLS 1.1".into(),
        0x0301 => "TLS 1.0".into(),
        0x0300 => "SSL 3.0".into(),
        _ => format!("0x{v:04x}"),
    }
}

/// True if TCP payload looks like a TLS handshake record.
pub fn looks_like_tls(payload: &[u8]) -> bool {
    payload.len() >= 5 && payload[0] == TLS_HANDSHAKE && matches!(payload[1], 0x03) && matches!(payload[2], 0x00..=0x04)
}
