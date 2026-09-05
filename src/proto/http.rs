//! HTTP/1.x request/response extraction (files, credentials, parameters, UA).

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;

use crate::case::{Case, Credential, Parameter};
use crate::extract::{self, SaveOpts};
use crate::reassembly::TcpStreamSide;

pub fn handle_stream(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    stream: &TcpStreamSide,
    _src: IpAddr,
    _dst: IpAddr,
    _sport: u16,
    _dport: u16,
) -> Result<()> {
    parse_exchange(
        case,
        output_dir,
        defang,
        &stream.request,
        &stream.response,
        stream.src_ip,
        stream.dst_ip,
    )
}

pub fn handle_segment(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    payload: &[u8],
    src: IpAddr,
    dst: IpAddr,
    _sport: u16,
    _dport: u16,
) -> Result<()> {
    if payload.starts_with(b"HTTP/1.") {
        parse_exchange(case, output_dir, defang, &[], payload, dst, src)?;
    } else if is_http_request(payload) {
        parse_request_only(case, payload, src, dst);
    }
    Ok(())
}

fn is_http_request(data: &[u8]) -> bool {
    data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"DELETE ")
}

fn parse_exchange(
    case: &mut Case,
    output_dir: &Path,
    defang: bool,
    request: &[u8],
    response: &[u8],
    client: IpAddr,
    server: IpAddr,
) -> Result<()> {
    if !request.is_empty() {
        parse_request_only(case, request, client, server);
    }
    if response.is_empty() || !response.starts_with(b"HTTP/1.") {
        return Ok(());
    }

    let (headers, body) = split_headers_body(response);
    let status_line = headers.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") && !status_line.contains(" 200\r") && !status_line.contains(" 20") {
        return Ok(());
    }

    let content_type = header_value(&headers, "content-type");
    let content_encoding = header_value(&headers, "content-encoding");
    let mut body = body.to_vec();
    if content_encoding.as_deref() == Some("gzip") {
        case.anomalies.push(crate::case::Anomaly {
            kind: "http".into(),
            detail: "gzip Content-Encoding not inflated".into(),
            frame: 0,
        });
    }

    if let Some(cl) = header_value(&headers, "content-length") {
        if let Ok(n) = cl.trim().parse::<usize>() {
            if body.len() > n {
                body.truncate(n);
            }
        }
    }

    if body.is_empty() {
        return Ok(());
    }

    let name = filename_from_request(request)
        .or_else(|| filename_from_content_type(content_type.as_deref()))
        .unwrap_or_else(|| {
            format!(
                "http_object_{}.bin",
                extract::hex_sha256(&body).chars().take(8).collect::<String>()
            )
        });

    extract::save_extracted(
        case,
        &name,
        body,
        SaveOpts {
            output_dir,
            defang,
            protocol: "HTTP",
            source_host: Some(server),
            dest_host: Some(client),
            content_type,
        },
    )
}

fn parse_request_only(case: &mut Case, request: &[u8], client: IpAddr, server: IpAddr) {
    let text = String::from_utf8_lossy(request);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some(p) => p,
        None => (text.as_ref(), ""),
    };
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let parts: Vec<_> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET");
    let path = parts.get(1).copied().unwrap_or("/");

    let mut host_hdr = String::new();
    let mut referer = None;
    let mut ua = None;

    if let Some((_, query)) = path.split_once('?') {
        for pair in query.split('&') {
            let (n, v) = pair.split_once('=').unwrap_or((pair, ""));
            if !n.is_empty() {
                case.parameters.push(Parameter {
                    name: url_decode(n),
                    value: url_decode(v),
                    source: "HTTP query".into(),
                    host: Some(server),
                });
            }
        }
    }

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("User-Agent") {
                ua = Some(value.to_string());
                let host = case.ensure_host(client);
                if !host.user_agents.iter().any(|u| u == value) {
                    host.user_agents.push(value.to_string());
                }
            }
            if name.eq_ignore_ascii_case("Cookie") {
                for pair in value.split(';') {
                    let (n, v) = pair.trim().split_once('=').unwrap_or((pair.trim(), ""));
                    case.parameters.push(Parameter {
                        name: n.to_string(),
                        value: v.to_string(),
                        source: "HTTP cookie".into(),
                        host: Some(server),
                    });
                    case.credentials.push(Credential {
                        protocol: "HTTP Cookie".into(),
                        username: n.to_string(),
                        secret: v.to_string(),
                        host: Some(server),
                        details: path.to_string(),
                    });
                }
            }
            if name.eq_ignore_ascii_case("Authorization") {
                if let Some(b64) = value
                    .strip_prefix("Basic ")
                    .or_else(|| value.strip_prefix("basic "))
                {
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        b64.trim(),
                    ) {
                        let s = String::from_utf8_lossy(&decoded);
                        let (user, pass) = s.split_once(':').unwrap_or((s.as_ref(), ""));
                        case.credentials.push(Credential {
                            protocol: "HTTP Basic".into(),
                            username: user.to_string(),
                            secret: pass.to_string(),
                            host: Some(server),
                            details: path.to_string(),
                        });
                    }
                }
            }
            if name.eq_ignore_ascii_case("Host") {
                host_hdr = value.to_string();
                let host = case.ensure_host(server);
                if !host.hostnames.iter().any(|h| h == value) {
                    host.hostnames.push(value.to_string());
                }
            }
            if name.eq_ignore_ascii_case("Referer") || name.eq_ignore_ascii_case("Referrer") {
                referer = Some(value.to_string());
            }
        }
    }

    if !host_hdr.is_empty() || path != "/" {
        let server_s = server.to_string();
        let host_for_hop = if host_hdr.is_empty() {
            server_s.as_str()
        } else {
            host_hdr.as_str()
        };
        crate::fingerprint::browser::push_hop(
            case,
            client,
            host_for_hop,
            path,
            method,
            referer.as_deref(),
            ua.as_deref(),
        );
    }

    if request_line.starts_with("POST") && !body.is_empty() {
        for pair in body.split('&') {
            let (n, v) = pair.split_once('=').unwrap_or((pair, ""));
            if !n.is_empty() {
                case.parameters.push(Parameter {
                    name: url_decode(n),
                    value: url_decode(v),
                    source: "HTTP POST".into(),
                    host: Some(server),
                });
            }
        }
    }
}

fn split_headers_body(data: &[u8]) -> (String, &[u8]) {
    if let Some(pos) = find_subsequence(data, b"\r\n\r\n") {
        let headers = String::from_utf8_lossy(&data[..pos]).into_owned();
        (headers, &data[pos + 4..])
    } else {
        (String::from_utf8_lossy(data).into_owned(), &[])
    }
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines().skip(1) {
        if let Some((n, v)) = line.split_once(':') {
            if n.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn filename_from_request(request: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(request);
    let line = text.lines().next()?;
    let path = line.split_whitespace().nth(1)?;
    let path = path.split('?').next()?;
    let name = path.rsplit('/').next()?;
    if name.is_empty() || name == path {
        None
    } else {
        Some(extract::sanitize_filename(name))
    }
}

fn filename_from_content_type(ct: Option<&str>) -> Option<String> {
    let ct = ct?.to_ascii_lowercase();
    let ext = if ct.contains("html") {
        "html"
    } else if ct.contains("jpeg") || ct.contains("jpg") {
        "jpg"
    } else if ct.contains("png") {
        "png"
    } else if ct.contains("gif") {
        "gif"
    } else if ct.contains("json") {
        "json"
    } else if ct.contains("javascript") {
        "js"
    } else {
        return None;
    };
    Some(format!("object.{ext}"))
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                if let Ok(v) =
                    u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
