//! TCP/UDP session tracking and minimal TCP stream buffering.

use std::collections::HashMap;
use std::net::IpAddr;

use etherparse::TcpSlice;

use crate::case::Session;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    a_ip: IpAddr,
    a_port: u16,
    b_ip: IpAddr,
    b_port: u16,
    proto: String,
}

impl FlowKey {
    fn canonical(proto: &str, src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> (Self, bool) {
        let forward = (src, sport) <= (dst, dport);
        let key = if forward {
            FlowKey {
                a_ip: src,
                a_port: sport,
                b_ip: dst,
                b_port: dport,
                proto: proto.to_string(),
            }
        } else {
            FlowKey {
                a_ip: dst,
                a_port: dport,
                b_ip: src,
                b_port: sport,
                proto: proto.to_string(),
            }
        };
        (key, forward)
    }
}

#[derive(Debug, Default)]
struct FlowStats {
    bytes_a_to_b: u64,
    bytes_b_to_a: u64,
    packets: u64,
    start_ts: Option<f64>,
    end_ts: Option<f64>,
}

#[derive(Debug, Default)]
struct TcpBuf {
    /// Concatenated client→server payload (best-effort, no full seq reordering yet).
    client_to_server: Vec<u8>,
    server_to_client: Vec<u8>,
}

pub struct SessionTracker {
    flows: HashMap<FlowKey, FlowStats>,
    tcp_bufs: HashMap<FlowKey, TcpBuf>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            tcp_bufs: HashMap::new(),
        }
    }

    pub fn observe(
        &mut self,
        proto: &str,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        nbytes: u64,
        ts: f64,
    ) {
        let (key, forward) = FlowKey::canonical(proto, src, sport, dst, dport);
        let stats = self.flows.entry(key).or_default();
        stats.packets += 1;
        if forward {
            stats.bytes_a_to_b += nbytes;
        } else {
            stats.bytes_b_to_a += nbytes;
        }
        if stats.start_ts.is_none() {
            stats.start_ts = Some(ts);
        }
        stats.end_ts = Some(ts);
    }

    /// Feed TCP payload; returns a completed HTTP-looking stream side when useful.
    pub fn feed_tcp(
        &mut self,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        _tcp: TcpSlice<'_>,
        payload: &[u8],
    ) -> Option<TcpStreamSide> {
        if payload.is_empty() {
            return None;
        }
        let (key, forward) = FlowKey::canonical("TCP", src, sport, dst, dport);
        let buf = self.tcp_bufs.entry(key.clone()).or_default();
        if forward {
            buf.client_to_server.extend_from_slice(payload);
            if looks_like_http_response(&buf.server_to_client)
                || looks_like_http_request(&buf.client_to_server)
            {
                return Some(TcpStreamSide {
                    request: buf.client_to_server.clone(),
                    response: buf.server_to_client.clone(),
                    src_ip: key.a_ip,
                    src_port: key.a_port,
                    dst_ip: key.b_ip,
                    dst_port: key.b_port,
                });
            }
        } else {
            buf.server_to_client.extend_from_slice(payload);
            if looks_like_http_response(&buf.server_to_client) {
                return Some(TcpStreamSide {
                    request: buf.client_to_server.clone(),
                    response: buf.server_to_client.clone(),
                    src_ip: key.a_ip,
                    src_port: key.a_port,
                    dst_ip: key.b_ip,
                    dst_port: key.b_port,
                });
            }
        }
        None
    }

    pub fn into_sessions(self) -> Vec<Session> {
        let mut out: Vec<_> = self
            .flows
            .into_iter()
            .map(|(k, s)| Session {
                proto: k.proto,
                src: k.a_ip,
                sport: k.a_port,
                dst: k.b_ip,
                dport: k.b_port,
                bytes_a_to_b: s.bytes_a_to_b,
                bytes_b_to_a: s.bytes_b_to_a,
                packets: s.packets,
                start_ts: s.start_ts,
                end_ts: s.end_ts,
                pipi: None,
                app_proto: None,
            })
            .collect();
        out.sort_by(|a, b| a.src.cmp(&b.src).then(a.sport.cmp(&b.sport)));
        out
    }
}

#[derive(Debug, Clone)]
pub struct TcpStreamSide {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

fn looks_like_http_request(data: &[u8]) -> bool {
    const METHODS: [&[u8]; 7] = [
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"OPTIONS ", b"DELETE ", b"PATCH ",
    ];
    METHODS.iter().any(|m| data.starts_with(m))
}

fn looks_like_http_response(data: &[u8]) -> bool {
    data.starts_with(b"HTTP/1.")
}
