//! Link / network / transport decode and tunnel decapsulation.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::Result;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::capture::{self, KeywordPattern};
use crate::case::Case;
use crate::fingerprint;
use crate::proto::{chat_ics, dns, ftp, http, http2, lpr, mail, smb, tftp, tls, voip};
use crate::reassembly::SessionTracker;

#[derive(Default)]
pub struct DecodeState {
    pub tftp: tftp::TftpState,
    pub voip: voip::VoipState,
    pub pipi_hints: HashMap<(IpAddr, u16, IpAddr, u16), String>,
}

impl DecodeState {
    pub fn new() -> Self {
        Self {
            tftp: tftp::TftpState::new(),
            voip: voip::VoipState::new(),
            pipi_hints: HashMap::new(),
        }
    }
}

pub(crate) fn process_frame(
    case: &mut Case,
    tracker: &mut SessionTracker,
    state: &mut DecodeState,
    output_dir: &Path,
    defang: bool,
    keywords: &[KeywordPattern],
    frame: u64,
    ts: f64,
    data: &[u8],
) -> Result<()> {
    let payload = strip_link_and_tunnels(data);
    process_ip_packet(
        case, tracker, state, output_dir, defang, keywords, frame, ts, &payload,
    )
}

fn process_ip_packet(
    case: &mut Case,
    tracker: &mut SessionTracker,
    state: &mut DecodeState,
    output_dir: &Path,
    defang: bool,
    keywords: &[KeywordPattern],
    frame: u64,
    ts: f64,
    data: &[u8],
) -> Result<()> {
    let Ok(sliced) = SlicedPacket::from_ethernet(data).or_else(|_| SlicedPacket::from_ip(data)) else {
        return Ok(());
    };

    let (src_ip, dst_ip, l3_len, ip_protocol, ip_payload) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (
                IpAddr::V4(Ipv4Addr::from(h.source())),
                IpAddr::V4(Ipv4Addr::from(h.destination())),
                v4.payload().payload.len() as u64,
                h.protocol(),
                v4.payload().payload.to_vec(),
            )
        }
        Some(NetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (
                IpAddr::V6(Ipv6Addr::from(h.source())),
                IpAddr::V6(Ipv6Addr::from(h.destination())),
                v6.payload().payload.len() as u64,
                h.next_header(),
                v6.payload().payload.to_vec(),
            )
        }
        None => return Ok(()),
    };

    case.ensure_host(src_ip).bytes_sent += l3_len;
    case.ensure_host(dst_ip).bytes_recv += l3_len;

    // GRE (IP protocol 47)
    if u8::from(ip_protocol) == 47 {
        if let Some(inner) = peel_gre(&ip_payload) {
            return process_ip_packet(
                case, tracker, state, output_dir, defang, keywords, frame, ts, &inner,
            );
        }
    }

    match sliced.transport {
        Some(TransportSlice::Udp(udp)) => {
            let sport = udp.source_port();
            let dport = udp.destination_port();
            let payload = udp.payload();

            tracker.observe("UDP", src_ip, sport, dst_ip, dport, payload.len() as u64, ts);
            note_ports(case, src_ip, sport, dst_ip, dport);
            note_pipi(state, src_ip, sport, dst_ip, dport, payload);

            // VXLAN: UDP 4789
            if sport == 4789 || dport == 4789 {
                if let Some(inner) = peel_vxlan(payload) {
                    return process_ip_packet(
                        case, tracker, state, output_dir, defang, keywords, frame, ts, &inner,
                    );
                }
            }

            if sport == 53 || dport == 53 {
                dns::handle(case, src_ip, dst_ip, payload, frame);
            }
            tftp::handle(
                case, &mut state.tftp, output_dir, defang, payload, src_ip, dst_ip, sport, dport,
            )?;
            voip::handle_udp(
                case, &mut state.voip, output_dir, payload, src_ip, dst_ip, sport, dport,
            )?;

            let session = format!("{src_ip}:{sport} ↔ {dst_ip}:{dport}/UDP");
            capture::match_keywords(case, keywords, payload, frame, &session);
        }
        Some(TransportSlice::Tcp(tcp)) => {
            let sport = tcp.source_port();
            let dport = tcp.destination_port();
            let payload = tcp.payload();

            tracker.observe("TCP", src_ip, sport, dst_ip, dport, payload.len() as u64, ts);
            note_ports(case, src_ip, sport, dst_ip, dport);
            if !payload.is_empty() {
                note_pipi(state, src_ip, sport, dst_ip, dport, payload);

                // OpenFlow PACKET_IN (controller port 6653/6633)
                if matches!(sport, 6633 | 6653) || matches!(dport, 6633 | 6653) {
                    if let Some(inner) = peel_openflow(payload) {
                        return process_ip_packet(
                            case, tracker, state, output_dir, defang, keywords, frame, ts, &inner,
                        );
                    }
                }

                // SOCKS5 CONNECT success may prepend tunneled payload in same segment
                let payload = peel_socks5_payload(payload).unwrap_or(payload);

                let assembled = tracker.feed_tcp(src_ip, sport, dst_ip, dport, tcp, payload);
                if let Some(stream) = assembled {
                    http::handle_stream(
                        case, output_dir, defang, &stream, src_ip, dst_ip, sport, dport,
                    )?;
                }
                http::handle_segment(
                    case, output_dir, defang, payload, src_ip, dst_ip, sport, dport,
                )?;
                http2::handle_segment(case, output_dir, defang, payload, src_ip, dst_ip)?;
                ftp::handle_segment(case, payload, src_ip, dst_ip, sport, dport);
                mail::handle_segment(case, payload, src_ip, dst_ip, sport, dport);
                smb::handle_segment(
                    case, output_dir, defang, payload, src_ip, dst_ip, sport, dport,
                )?;
                chat_ics::handle_segment(
                    case, output_dir, defang, payload, src_ip, dst_ip, sport, dport,
                )?;
                lpr::handle_segment(
                    case, output_dir, defang, payload, src_ip, dst_ip, sport, dport,
                )?;
                if tls::looks_like_tls(payload)
                    || matches!(sport, 443 | 465 | 993 | 995 | 8443)
                    || matches!(dport, 443 | 465 | 993 | 995 | 8443)
                {
                    tls::handle_segment(
                        case, output_dir, defang, payload, src_ip, dst_ip, sport, dport, frame,
                    )?;
                }
            }

            let session = format!("{src_ip}:{sport} ↔ {dst_ip}:{dport}/TCP");
            capture::match_keywords(case, keywords, payload, frame, &session);
        }
        _ => {}
    }

    Ok(())
}

/// Finalize protocol state after all frames (e.g. flush VoIP RTP → WAV).
pub fn finalize(case: &mut Case, state: &mut DecodeState, output_dir: &Path) -> Result<()> {
    voip::finalize(case, &mut state.voip, output_dir)
}

fn note_ports(case: &mut Case, src: IpAddr, sport: u16, dst: IpAddr, dport: u16) {
    for (ip, port) in [(src, sport), (dst, dport)] {
        let host = case.ensure_host(ip);
        if !host.open_ports.contains(&port) && port != 0 {
            host.open_ports.push(port);
            host.open_ports.sort_unstable();
        }
    }
}

fn note_pipi(
    state: &mut DecodeState,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    payload: &[u8],
) {
    if let Some(name) = fingerprint::identify_payload(payload) {
        state
            .pipi_hints
            .entry((src, sport, dst, dport))
            .or_insert_with(|| name.to_string());
    }
}

/// Strip Ethernet and common tunnel headers (VLAN, QinQ, PPPoE, MPLS) until IP-bearing frame.
fn strip_link_and_tunnels(data: &[u8]) -> Vec<u8> {
    let mut cur = data.to_vec();

    // Peel stacked 802.1Q / 802.1ad
    loop {
        if cur.len() >= 18 && matches!((cur[12], cur[13]), (0x81, 0x00) | (0x88, 0xa8) | (0x91, 0x00))
        {
            let mut out = cur[..12].to_vec();
            out.extend_from_slice(&cur[16..]);
            cur = out;
            continue;
        }
        break;
    }

    // MPLS unicast 0x8847 / multicast 0x8848 — peel labels until BOS
    if cur.len() >= 14 && matches!((cur[12], cur[13]), (0x88, 0x47) | (0x88, 0x48)) {
        let mut off = 14usize;
        while off + 4 <= cur.len() {
            let bos = cur[off + 2] & 0x01 != 0;
            off += 4;
            if bos {
                break;
            }
        }
        // Heuristic: remaining is Ethernet or IP
        if off < cur.len() {
            let rest = &cur[off..];
            if rest.len() >= 1 && matches!(rest[0], 0x45..=0x4f | 0x60..=0x6f) {
                // raw IP after MPLS
                return rest.to_vec();
            }
            return rest.to_vec();
        }
    }

    // PPPoE session 0x8864: dst(6) src(6) ethertype(2) ver/type(1) code(1) session(2) len(2) PPP proto(2)
    if cur.len() >= 20 && cur[12] == 0x88 && cur[13] == 0x64 {
        let ppp_proto = u16::from_be_bytes([cur[18], cur[19]]);
        let inner = &cur[20..];
        if ppp_proto == 0x0021 {
            // IPv4
            let mut eth = vec![0u8; 12];
            eth.extend_from_slice(&[0x08, 0x00]);
            eth.extend_from_slice(inner);
            return eth;
        } else if ppp_proto == 0x0057 {
            let mut eth = vec![0u8; 12];
            eth.extend_from_slice(&[0x86, 0xdd]);
            eth.extend_from_slice(inner);
            return eth;
        }
    }

    cur
}

fn peel_gre(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 4 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[0], payload[1]]);
    let protocol = u16::from_be_bytes([payload[2], payload[3]]);
    let mut off = 4usize;
    if flags & 0x8000 != 0 {
        off += 4; // checksum/reserved
    }
    if flags & 0x2000 != 0 {
        off += 4; // key
    }
    if flags & 0x1000 != 0 {
        off += 4; // seq
    }
    if off > payload.len() {
        return None;
    }
    let inner = &payload[off..];
    match protocol {
        0x0800 => {
            // IPv4 — wrap as ethertype for from_ip or synthesize ethernet
            let mut eth = vec![0u8; 12];
            eth.extend_from_slice(&[0x08, 0x00]);
            eth.extend_from_slice(inner);
            Some(eth)
        }
        0x86DD => {
            let mut eth = vec![0u8; 12];
            eth.extend_from_slice(&[0x86, 0xdd]);
            eth.extend_from_slice(inner);
            Some(eth)
        }
        // ERSPAN over GRE
        0x88BE => {
            if inner.len() > 8 {
                Some(inner[8..].to_vec())
            } else {
                None
            }
        }
        0x22EB => {
            if inner.len() > 12 {
                Some(inner[12..].to_vec())
            } else {
                None
            }
        }
        0x6558 => Some(inner.to_vec()),
        _ => None,
    }
}

fn peel_vxlan(payload: &[u8]) -> Option<Vec<u8>> {
    // Flags(1) reserved(3) VNI(3) reserved(1) + inner Ethernet
    if payload.len() < 8 {
        return None;
    }
    Some(payload[8..].to_vec())
}

/// OpenFlow PACKET_IN (type 10): version(1) type(1) len(2) xid(4) then buffer/total/reason/table/cookie… then Ethernet.
fn peel_openflow(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 16 {
        return None;
    }
    let version = payload[0];
    let typ = payload[1];
    if version < 1 || version > 6 || typ != 10 {
        return None;
    }
    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if total_len > payload.len() || total_len < 24 {
        return None;
    }
    // OF1.0 PACKET_IN: after 8-byte header, buffer_id(4) total_len(2) in_port(2) reason(1) pad(1) = offset 18
    // OF1.3+: longer; scan for Ethernet dest MAC + EtherType pattern
    for start in [16usize, 24, 32, 40] {
        if start + 14 <= payload.len() {
            let ethertype = u16::from_be_bytes([payload[start + 12], payload[start + 13]]);
            if matches!(ethertype, 0x0800 | 0x86dd | 0x0806 | 0x8100) {
                return Some(payload[start..].to_vec());
            }
        }
    }
    None
}

/// After SOCKS5 CONNECT success (0x05 0x00 …), remaining bytes are the tunneled stream start.
fn peel_socks5_payload(payload: &[u8]) -> Option<&[u8]> {
    // Client greeting: 0x05 nmethods methods…
    // Server choice: 0x05 method
    // Request reply success: 05 00 00 atyp …
    if payload.len() >= 2 && payload[0] == 0x05 && payload[1] == 0x00 {
        // Could be method selection (len>=2) or reply
        if payload.len() >= 10 && payload.get(2) == Some(&0x00) {
            // reply: ver method rsv atyp
            let atyp = *payload.get(3)?;
            let skip = match atyp {
                0x01 => 4 + 4 + 2, // IPv4
                0x03 => {
                    let n = *payload.get(4)? as usize;
                    4 + 1 + n + 2
                }
                0x04 => 4 + 16 + 2, // IPv6
                _ => return None,
            };
            if payload.len() > skip {
                return Some(&payload[skip..]);
            }
        }
    }
    None
}
