//! Integration: PCAP → hosts / sessions / DNS / HTTP file.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use etherparse::PacketBuilder;
use hostsight::capture::{self, IngestOptions};
use tempfile::tempdir;

fn write_pcap(path: &PathBuf, packets: &[Vec<u8>]) {
    // Classic PCAP global header (little-endian, Ethernet, snaplen 65535)
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, // magic
        0x02, 0x00, 0x04, 0x00, // v2.4
        0x00, 0x00, 0x00, 0x00, // thiszone
        0x00, 0x00, 0x00, 0x00, // sigfigs
        0xff, 0xff, 0x00, 0x00, // snaplen
        0x01, 0x00, 0x00, 0x00, // LINKTYPE_ETHERNET
    ])
    .unwrap();

    for (i, pkt) in packets.iter().enumerate() {
        let ts_sec = (i as u32).to_le_bytes();
        let ts_usec = [0u8; 4];
        let incl = (pkt.len() as u32).to_le_bytes();
        f.write_all(&ts_sec).unwrap();
        f.write_all(&ts_usec).unwrap();
        f.write_all(&incl).unwrap();
        f.write_all(&incl).unwrap();
        f.write_all(pkt).unwrap();
    }
}

fn eth_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn eth_ipv4_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, seq, 8192)
        .ack(ack);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

/// Build a DNS query for example.com A
fn dns_query_example_com() -> Vec<u8> {
    let mut p = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags RD
        0x00, 0x01, // qd
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["example", "com"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    p
}

fn dns_response_example_com() -> Vec<u8> {
    let mut p = dns_query_example_com();
    p[2] = 0x81;
    p[3] = 0x80;
    p[6] = 0x00;
    p[7] = 0x01; // ancount=1
    // answer: pointer to name, A, IN, TTL, RDLEN 4, 93.184.216.34
    p.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34,
    ]);
    p
}

#[test]
fn pcap_populates_hosts_sessions_dns_and_http_file() {
    let dir = tempdir().unwrap();
    let pcap_path = dir.path().join("sample.pcap");
    let out_dir = dir.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let client = Ipv4Addr::new(10, 0, 0, 1);
    let dns_srv = Ipv4Addr::new(10, 0, 0, 53);
    let http_srv = Ipv4Addr::new(93, 184, 216, 34);

    let http_req = b"GET /hello.txt HTTP/1.1\r\nHost: example.com\r\nUser-Agent: HostSightTest/1.0\r\n\r\n";
    let http_body = b"hello from hostsight fixture";
    let http_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        http_body.len()
    );
    let mut resp = http_resp.into_bytes();
    resp.extend_from_slice(http_body);

    let packets = vec![
        eth_ipv4_udp(client, dns_srv, 53000, 53, &dns_query_example_com()),
        eth_ipv4_udp(dns_srv, client, 53, 53000, &dns_response_example_com()),
        eth_ipv4_tcp(client, http_srv, 40000, 80, 1, 0, http_req),
        eth_ipv4_tcp(http_srv, client, 80, 40000, 1, (http_req.len() as u32) + 1, &resp),
    ];
    write_pcap(&pcap_path, &packets);

    let case = capture::ingest_file(
        &pcap_path,
        &out_dir,
        &IngestOptions {
            keywords: "hello".into(),
            ..IngestOptions::default()
        },
    )
    .unwrap();

    assert!(
        case.hosts.contains_key(&std::net::IpAddr::V4(client)),
        "client host missing"
    );
    assert!(
        case.hosts.contains_key(&std::net::IpAddr::V4(http_srv)),
        "http server host missing"
    );
    assert!(!case.sessions.is_empty(), "expected sessions");
    assert!(
        case.dns_records.iter().any(|d| d.query.contains("example")),
        "expected DNS for example.com, got {:?}",
        case.dns_records
    );
    assert!(
        case.files.iter().any(|f| f.size == http_body.len() as u64),
        "expected HTTP file extract, got {:?}",
        case.files
    );
    assert!(
        case.keywords.iter().any(|k| k.keyword == "hello"),
        "expected keyword hit"
    );

    // silence unused import warning if SocketAddrV4 unused
    let _ = SocketAddrV4::new(client, 0);
}
