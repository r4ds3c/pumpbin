//! Phase 4: enrichment, PIPI, exports, CIDR filter.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use etherparse::PacketBuilder;
use hostsight::capture::{self, IngestOptions};
use hostsight::enrich::{self, GeoDb};
use hostsight::export;
use hostsight::fingerprint::{self, DecodeAsMap};
use hostsight::intel;
use tempfile::tempdir;

fn write_pcap(path: &PathBuf, packets: &[Vec<u8>]) {
    let mut f = std::fs::File::create(path).unwrap();
    capture::pcap_over_ip::write_pcap_stream(&mut f, packets).unwrap();
}

fn eth_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn eth_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 1, 8192)
        .ack(1);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn dns_query_example_com() -> Vec<u8> {
    let mut p = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["example", "com"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    p
}

#[test]
fn geo_and_whitelist_enrichment() {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("e.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let client = Ipv4Addr::new(10, 0, 0, 1);
    let dns = Ipv4Addr::new(8, 8, 8, 8);
    write_pcap(
        &pcap,
        &[eth_udp(client, dns, 53000, 53, &dns_query_example_com())],
    );

    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    let host = case.hosts.get(&std::net::IpAddr::V4(dns)).unwrap();
    assert_eq!(host.country.as_deref(), Some("US"));
    assert!(host.asn.as_deref().unwrap_or("").contains("15169"));
    assert!(
        case.dns_records.iter().any(|d| d.query.contains("example") && d.whitelisted),
        "{:?}",
        case.dns_records
    );
}

#[test]
fn pipi_detects_http_and_tls() {
    assert_eq!(fingerprint::identify_payload(b"GET / HTTP/1.1\r\n"), Some("HTTP"));
    assert_eq!(
        fingerprint::identify_payload(&[0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5]),
        Some("SSL/TLS")
    );
    assert_eq!(fingerprint::identify_payload(b"SSH-2.0-OpenSSH"), Some("SSH"));
}

#[test]
fn cidr_filter_keeps_matching_hosts() {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("c.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    write_pcap(
        &pcap,
        &[eth_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            1,
            53,
            &dns_query_example_com(),
        )],
    );
    let mut opts = IngestOptions::default();
    opts.cidr_filter = "10.0.0.0/8".into();
    let case = capture::ingest_file(&pcap, &out, &opts).unwrap();
    assert!(case.hosts.contains_key(&std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(!case.hosts.contains_key(&std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn export_all_counts_match_case() {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("x.pcap");
    let out = dir.path().join("out");
    let exp = dir.path().join("export");
    std::fs::create_dir_all(&out).unwrap();

    let c = Ipv4Addr::new(10, 9, 9, 1);
    let s = Ipv4Addr::new(10, 9, 9, 2);
    let req = b"GET /p.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1\r\n\r\n";
    let body = b"hi";
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    write_pcap(
        &pcap,
        &[
            eth_udp(c, Ipv4Addr::new(8, 8, 8, 8), 53000, 53, &dns_query_example_com()),
            eth_tcp(c, s, 40000, 80, req),
            eth_tcp(s, c, 80, 40000, &resp),
        ],
    );

    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    let m = export::export_all(&case, &exp).unwrap();
    assert_eq!(m.hosts, case.hosts.len());
    assert_eq!(m.sessions, case.sessions.len());
    assert_eq!(m.dns, case.dns_records.len());
    assert_eq!(m.files, case.files.len());
    assert!(exp.join("case.xml").exists());
    assert!(exp.join("case.case.json").exists());
    assert!(exp.join("case.jsonld").exists());
    assert!(exp.join("hosts_excel.csv").exists());
    assert!(!case.browser_traces.is_empty());
}

#[test]
fn decode_as_and_geo_db_load() {
    let mut map = DecodeAsMap::builtin();
    map.tcp.insert(8443, "HTTPS-ALT".into());
    assert_eq!(map.resolve("TCP", 8443), Some("HTTPS-ALT"));
    let geo = GeoDb::builtin();
    assert!(geo.lookup("8.8.8.8".parse().unwrap()).is_some());
    let dir = tempdir().unwrap();
    enrich::write_sample_dbs(dir.path()).unwrap();
    assert!(dir.path().join("geo.csv").exists());
}

#[test]
fn tracker_detection() {
    assert!(enrich::is_tracker_or_ad("pagead2.googlesyndication.com"));
    assert!(!enrich::is_tracker_or_ad("example.com"));
}

#[test]
fn parse_cidr_list_ok() {
    let v = intel::parse_cidr_list("10.0.0.0/8, 192.168.0.0/16").unwrap();
    assert_eq!(v.len(), 2);
}
