//! Minimal DNS query/response parser (UDP/53).

use std::net::IpAddr;

use crate::case::{Case, DnsRecord};

pub fn handle(case: &mut Case, src: IpAddr, dst: IpAddr, payload: &[u8], frame: u64) {
    if payload.len() < 12 {
        return;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if qdcount == 0 {
        return;
    }

    let mut offset = 12usize;
    let Some((name, next)) = read_name(payload, offset) else {
        return;
    };
    offset = next;
    if offset + 4 > payload.len() {
        return;
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 4; // qtype + qclass

    let mut answers = Vec::new();
    let is_response = flags & 0x8000 != 0;
    if is_response {
        for _ in 0..ancount {
            let Some((_n, n_off)) = read_name(payload, offset) else {
                break;
            };
            offset = n_off;
            if offset + 10 > payload.len() {
                break;
            }
            let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let rdlen = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
            offset += 10;
            if offset + rdlen > payload.len() {
                break;
            }
            let rdata = &payload[offset..offset + rdlen];
            offset += rdlen;
            if let Some(ans) = format_rdata(rtype, rdata) {
                answers.push(ans);
            }
        }
    }

    let (client, server) = if is_response {
        (Some(dst), Some(src))
    } else {
        (Some(src), Some(dst))
    };

    // Hostnames on client and any A/AAAA answers
    if let Some(c) = client {
        let host = case.ensure_host(c);
        if !host.hostnames.contains(&name) {
            host.hostnames.push(name.clone());
        }
    }
    for ans in &answers {
        if let Ok(ip) = ans.parse::<IpAddr>() {
            let host = case.ensure_host(ip);
            if !host.hostnames.contains(&name) {
                host.hostnames.push(name.clone());
            }
        }
    }

    case.dns_records.push(DnsRecord {
        query: name,
        qtype: qtype_name(qtype).into(),
        answers,
        client,
        server,
        frame,
        whitelisted: false,
        is_tracker: false,
    });
}

fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "OTHER",
    }
}

fn format_rdata(rtype: u16, rdata: &[u8]) -> Option<String> {
    match rtype {
        1 if rdata.len() == 4 => Some(format!(
            "{}.{}.{}.{}",
            rdata[0], rdata[1], rdata[2], rdata[3]
        )),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        5 | 12 => read_name(rdata, 0).map(|(n, _)| n),
        16 => {
            if rdata.is_empty() {
                return None;
            }
            let len = rdata[0] as usize;
            if 1 + len <= rdata.len() {
                Some(String::from_utf8_lossy(&rdata[1..1 + len]).into_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn read_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;
    let mut hops = 0;

    loop {
        if offset >= data.len() || hops > 16 {
            return None;
        }
        let len = data[offset];
        if len == 0 {
            offset += 1;
            if !jumped {
                return_offset = offset;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let ptr = (((len as usize) & 0x3F) << 8) | data[offset + 1] as usize;
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            hops += 1;
            continue;
        }
        offset += 1;
        let end = offset + len as usize;
        if end > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[offset..end]).into_owned());
        offset = end;
    }

    Some((labels.join("."), return_offset))
}
