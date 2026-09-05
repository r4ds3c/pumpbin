//! OS / OUI / PIPI fingerprinting and user decode-as maps.

pub mod browser;

use std::collections::HashMap;
use std::net::IpAddr;

use crate::case::{Case, Session};

/// User-defined port → protocol name (“decode as”).
#[derive(Debug, Clone, Default)]
pub struct DecodeAsMap {
    pub tcp: HashMap<u16, String>,
    pub udp: HashMap<u16, String>,
}

impl DecodeAsMap {
    pub fn builtin() -> Self {
        let mut m = Self::default();
        for (p, n) in [
            (21u16, "FTP"),
            (22, "SSH"),
            (23, "Telnet"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (110, "POP3"),
            (143, "IMAP"),
            (443, "HTTPS"),
            (445, "SMB"),
            (3389, "RDP"),
            (5060, "SIP"),
        ] {
            m.tcp.insert(p, n.into());
        }
        m.udp.insert(53, "DNS".into());
        m.udp.insert(69, "TFTP".into());
        m.udp.insert(123, "NTP".into());
        m.udp.insert(161, "SNMP".into());
        m.udp.insert(5060, "SIP".into());
        m
    }

    pub fn resolve(&self, transport: &str, port: u16) -> Option<&str> {
        match transport.to_ascii_uppercase().as_str() {
            "TCP" => self.tcp.get(&port).map(|s| s.as_str()),
            "UDP" => self.udp.get(&port).map(|s| s.as_str()),
            _ => None,
        }
    }
}

/// Port-Independent Protocol Identification from payload bytes.
pub fn identify_payload(payload: &[u8]) -> Option<&'static str> {
    if payload.is_empty() {
        return None;
    }
    if payload.len() >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
        return Some("SSL/TLS");
    }
    if payload.starts_with(b"SSH-") {
        return Some("SSH");
    }
    if payload.starts_with(b"HTTP/1.")
        || payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"HEAD ")
    {
        return Some("HTTP");
    }
    if payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return Some("HTTP/2");
    }
    if payload.starts_with(b"220 ")
        && (payload.windows(3).any(|w| w == b"FTP") || payload.windows(4).any(|w| w == b"ftp"))
    {
        return Some("FTP");
    }
    if looks_dns(payload) {
        return Some("DNS");
    }
    if payload.starts_with(b"NICK ") || payload.starts_with(b"USER ") && payload.windows(5).any(|w| w == b"JOIN ")
    {
        return Some("IRC");
    }
    if payload.starts_with(b"\x05") && payload.len() >= 2 {
        // SOCKS5 version
        return Some("SOCKS");
    }
    if payload.starts_with(b"\x04") && payload.len() >= 8 {
        return Some("SOCKS");
    }
    if payload.starts_with(b"\xffSMB") || (payload.len() >= 8 && &payload[4..8] == b"\xfeSMB") {
        return Some("SMB");
    }
    if payload.starts_with(b"\x12\x01") {
        // TDS PRELOGIN-ish
        return Some("TDS/MS-SQL");
    }
    if payload.starts_with(b"\x03\x00") && payload.len() >= 4 {
        // TPKT
        return Some("TPKT");
    }
    if payload.windows(8).any(|w| w == b"Meterpreter" || w == b"metsrv.x") {
        return Some("Meterpreter");
    }
    if payload.windows(4).any(|w| w == b"SPOT") {
        return Some("Spotify");
    }
    if payload.starts_with(b"INVITE ") || payload.starts_with(b"SIP/2.0") {
        return Some("SIP");
    }
    None
}

fn looks_dns(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let qd = u16::from_be_bytes([payload[4], payload[5]]);
    let an = u16::from_be_bytes([payload[6], payload[7]]);
    qd <= 10 && an <= 50 && payload[2] & 0x78 == 0
}

/// Apply PIPI + decode-as labels onto sessions (best-effort from first payloads tracked elsewhere).
pub fn label_session(session: &mut Session, decode_as: &DecodeAsMap, pipi: Option<&str>) {
    if let Some(name) = pipi {
        session.pipi = Some(name.to_string());
        if session.proto == "TCP" || session.proto == "UDP" {
            session.app_proto = Some(name.to_string());
        }
    }
    let port_hint = decode_as
        .resolve(&session.proto, session.dport)
        .or_else(|| decode_as.resolve(&session.proto, session.sport));
    if session.app_proto.is_none() {
        if let Some(h) = port_hint {
            session.app_proto = Some(h.to_string());
        }
    }
}

pub fn oui_vendor(mac: &str) -> Option<String> {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() < 6 {
        return None;
    }
    let prefix = clean[..6].to_ascii_uppercase();
    // Tiny built-in OUI sample
    match prefix.as_str() {
        "000C29" | "005056" => Some("VMware".into()),
        "00155D" => Some("Microsoft Hyper-V".into()),
        "080027" | "0A0027" => Some("PCS Systemtechnik / VirtualBox".into()),
        "525400" => Some("QEMU/KVM".into()),
        "B827EB" | "DCA632" => Some("Raspberry Pi".into()),
        "F0D4E2" | "ACDE48" => Some("Apple".into()),
        _ => None,
    }
}

/// Basic passive OS guess from User-Agent / TTL-ish hints stored on host.
pub fn guess_os_from_ua(ua: &str) -> Option<String> {
    let u = ua.to_ascii_lowercase();
    if u.contains("windows nt 10") || u.contains("windows nt 11") {
        return Some("Windows 10/11".into());
    }
    if u.contains("windows nt") {
        return Some("Windows".into());
    }
    if u.contains("android") {
        return Some("Android".into());
    }
    if u.contains("iphone") || u.contains("ipad") || u.contains("ios") {
        return Some("iOS".into());
    }
    if u.contains("mac os x") || u.contains("macintosh") {
        return Some("macOS".into());
    }
    if u.contains("linux") {
        return Some("Linux".into());
    }
    None
}

/// Advanced-ish: combine UA + open ports heuristics.
pub fn advanced_os_guess(host: &crate::case::Host) -> Option<String> {
    for ua in &host.user_agents {
        if let Some(g) = guess_os_from_ua(ua) {
            return Some(format!("{g} (UA)"));
        }
    }
    let ports = &host.open_ports;
    if ports.contains(&445) && ports.contains(&139) {
        return Some("Windows (SMB ports)".into());
    }
    if ports.contains(&22) && !ports.contains(&445) {
        return Some("Unix-like (SSH)".into());
    }
    if ports.contains(&548) {
        return Some("macOS (AFP)".into());
    }
    None
}

pub fn enrich_hosts_os(case: &mut Case) {
    for host in case.hosts.values_mut() {
        if host.os_guess.is_none() {
            host.os_guess = advanced_os_guess(host);
        }
        if let Some(mac) = &host.mac {
            if host.oui_vendor.is_none() {
                host.oui_vendor = oui_vendor(mac);
            }
        }
    }
}

pub fn apply_pipi_to_case(case: &mut Case, decode_as: &DecodeAsMap, hints: &HashMap<(IpAddr, u16, IpAddr, u16), String>) {
    for s in &mut case.sessions {
        let key_fwd = (s.src, s.sport, s.dst, s.dport);
        let key_rev = (s.dst, s.dport, s.src, s.sport);
        let pipi = hints.get(&key_fwd).or_else(|| hints.get(&key_rev)).map(|s| s.as_str());
        label_session(s, decode_as, pipi);
    }
}
