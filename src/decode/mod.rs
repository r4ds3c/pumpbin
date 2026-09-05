//! Link / network / transport decode and tunnel decapsulation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::Result;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::capture::{self, KeywordPattern};
use crate::case::Case;
use crate::proto::{dns, ftp, http, http2, lpr, mail, smb, tftp, tls, voip};
use crate::reassembly::SessionTracker;

#[derive(Default)]
pub struct DecodeState {
    pub tftp: tftp::TftpState,
    pub voip: voip::VoipState,
}

impl DecodeState {
    pub fn new() -> Self {
        Self {
            tftp: tftp::TftpState::new(),
            voip: voip::VoipState::new(),
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
                smb::handle_segment(case, payload, src_ip, dst_ip, sport, dport);
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
        0x6558 => {
            // Transparent Ethernet bridging
            Some(inner.to_vec())
        }
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
