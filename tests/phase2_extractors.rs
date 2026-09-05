//! Phase 2 golden tests: FTP, TFTP, SMTP, TLS (SNI/JA3/certs), HTTP.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use etherparse::PacketBuilder;
use hostsight::capture::{self, IngestOptions};
use tempfile::tempdir;

fn write_pcap(path: &PathBuf, packets: &[Vec<u8>]) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ])
    .unwrap();
    for (i, pkt) in packets.iter().enumerate() {
        let ts_sec = (i as u32).to_le_bytes();
        let incl = (pkt.len() as u32).to_le_bytes();
        f.write_all(&ts_sec).unwrap();
        f.write_all(&[0; 4]).unwrap();
        f.write_all(&incl).unwrap();
        f.write_all(&incl).unwrap();
        f.write_all(pkt).unwrap();
    }
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

fn eth_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn ingest(packets: Vec<Vec<u8>>) -> hostsight::case::Case {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("t.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    write_pcap(&pcap, &packets);
    // Keep tempdir alive via leak of paths only — re-open after drop would fail.
    // So ingest before dir drops; files may be removed after but case is in memory.
    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    // Prevent early drop of extracted files during asserts that only check case metadata
    std::mem::forget(dir);
    case
}

#[test]
fn ftp_extracts_user_pass() {
    let c = Ipv4Addr::new(10, 0, 0, 2);
    let s = Ipv4Addr::new(10, 0, 0, 21);
    let case = ingest(vec![
        eth_tcp(c, s, 50000, 21, b"USER alice\r\n"),
        eth_tcp(c, s, 50000, 21, b"PASS s3cret\r\n"),
        eth_tcp(c, s, 50000, 21, b"RETR report.pdf\r\n"),
    ]);
    assert!(
        case.credentials
            .iter()
            .any(|x| x.protocol == "FTP" && x.username == "alice" && x.secret == "s3cret"),
        "{:?}",
        case.credentials
    );
    assert!(
        case.parameters
            .iter()
            .any(|p| p.name == "RETR" && p.value.contains("report.pdf")),
        "{:?}",
        case.parameters
    );
}

#[test]
fn tftp_extracts_file() {
    let c = Ipv4Addr::new(10, 0, 0, 3);
    let s = Ipv4Addr::new(10, 0, 0, 69);
    let mut rrq = vec![0x00, 0x01];
    rrq.extend_from_slice(b"boot.cfg");
    rrq.push(0);
    rrq.extend_from_slice(b"octet");
    rrq.push(0);
    let body = b"tftp-payload-bytes";
    let mut data = vec![0x00, 0x03, 0x00, 0x01];
    data.extend_from_slice(body);
    let case = ingest(vec![
        eth_udp(c, s, 4000, 69, &rrq),
        eth_udp(s, c, 69, 4000, &data),
    ]);
    assert!(
        case.files.iter().any(|f| f.protocol == "TFTP" && f.size == body.len() as u64),
        "{:?}",
        case.files
    );
}

#[test]
fn smtp_auth_plain_and_message() {
    let c = Ipv4Addr::new(10, 0, 0, 4);
    let s = Ipv4Addr::new(10, 0, 0, 25);
    // AUTH PLAIN: \0user\0pass -> base64
    let plain = b"\0bob\0hunter2";
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
    let auth = format!("AUTH PLAIN {b64}\r\n");
    let mail = b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.com>\r\nDATA\r\nSubject: Hi\r\n\r\nHello body\r\n.\r\n";
    let case = ingest(vec![
        eth_tcp(c, s, 50001, 25, auth.as_bytes()),
        eth_tcp(c, s, 50001, 25, mail),
    ]);
    assert!(
        case.credentials
            .iter()
            .any(|x| x.protocol.contains("SMTP") && x.username == "bob"),
        "{:?}",
        case.credentials
    );
    assert!(
        case.messages.iter().any(|m| m.protocol == "SMTP" && m.subject.contains("Hi")),
        "{:?}",
        case.messages
    );
}

#[test]
fn http_still_extracts() {
    let c = Ipv4Addr::new(10, 0, 0, 5);
    let s = Ipv4Addr::new(10, 0, 0, 80);
    let req = b"GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n";
    let body = b"abc123";
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    let case = ingest(vec![
        eth_tcp(c, s, 40001, 80, req),
        eth_tcp(s, c, 80, 40001, &resp),
    ]);
    assert!(case.files.iter().any(|f| f.protocol == "HTTP" && f.size == 6));
}

/// Minimal TLS ClientHello with SNI example.com + Certificate handshake with tiny DER blob.
#[test]
fn tls_sni_ja3_and_cert_file() {
    let c = Ipv4Addr::new(10, 0, 0, 6);
    let s = Ipv4Addr::new(10, 0, 0, 7);

    let client_hello_body = build_client_hello_with_sni(b"example.com");
    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    let len = client_hello_body.len();
    hs.push(((len >> 16) & 0xff) as u8);
    hs.push(((len >> 8) & 0xff) as u8);
    hs.push((len & 0xff) as u8);
    hs.extend_from_slice(&client_hello_body);
    let mut rec = vec![0x16, 0x03, 0x01];
    let rlen = hs.len() as u16;
    rec.extend_from_slice(&rlen.to_be_bytes());
    rec.extend_from_slice(&hs);

    // Certificate message with one "cert" (not valid X.509 — still extracted)
    let fake_der = b"\x30\x03\x01\x01\xff".to_vec(); // minimal ASN.1 BOOLEAN
    let mut cert_list = Vec::new();
    let clen = fake_der.len();
    cert_list.push(((clen >> 16) & 0xff) as u8);
    cert_list.push(((clen >> 8) & 0xff) as u8);
    cert_list.push((clen & 0xff) as u8);
    cert_list.extend_from_slice(&fake_der);
    let mut cert_body = Vec::new();
    let ll = cert_list.len();
    cert_body.push(((ll >> 16) & 0xff) as u8);
    cert_body.push(((ll >> 8) & 0xff) as u8);
    cert_body.push((ll & 0xff) as u8);
    cert_body.extend_from_slice(&cert_list);
    let mut cert_hs = vec![0x0b];
    let bl = cert_body.len();
    cert_hs.push(((bl >> 16) & 0xff) as u8);
    cert_hs.push(((bl >> 8) & 0xff) as u8);
    cert_hs.push((bl & 0xff) as u8);
    cert_hs.extend_from_slice(&cert_body);
    let mut cert_rec = vec![0x16, 0x03, 0x03];
    let crl = cert_hs.len() as u16;
    cert_rec.extend_from_slice(&crl.to_be_bytes());
    cert_rec.extend_from_slice(&cert_hs);

    let case = ingest(vec![
        eth_tcp(c, s, 50010, 443, &rec),
        eth_tcp(s, c, 443, 50010, &cert_rec),
    ]);

    assert!(
        case.tls_handshakes
            .iter()
            .any(|t| t.sni.as_deref() == Some("example.com") && t.ja3.is_some()),
        "{:?}",
        case.tls_handshakes
    );
    assert!(
        case.files.iter().any(|f| f.protocol == "TLS"),
        "{:?}",
        case.files
    );
}

fn build_client_hello_with_sni(sni: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id len
    // cipher suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x00, 0x04, 0x00, 0x2f, 0xc0, 0x2f]);
    body.push(1); // compression len
    body.push(0); // null

    // extensions: SNI + supported_groups + ec_point_formats
    let mut exts = Vec::new();
    // SNI
    let mut sni_ext = Vec::new();
    let name_list_len = 3 + sni.len();
    sni_ext.extend_from_slice(&(name_list_len as u16).to_be_bytes());
    sni_ext.push(0); // host_name
    sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni);
    exts.extend_from_slice(&[0x00, 0x00]); // type SNI
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);

    // supported_groups (0x000a): secp256r1
    let sg = [0x00, 0x02, 0x00, 0x17];
    exts.extend_from_slice(&[0x00, 0x0a]);
    exts.extend_from_slice(&(sg.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sg);

    // ec_point_formats (0x000b)
    let pf = [0x01, 0x00];
    exts.extend_from_slice(&[0x00, 0x0b]);
    exts.extend_from_slice(&(pf.len() as u16).to_be_bytes());
    exts.extend_from_slice(&pf);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    body
}
