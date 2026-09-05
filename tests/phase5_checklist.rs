//! Checklist stretch: ETL, PacketCache, IRC/IEC/njRAT, ERSPAN, SMB2 READ.

use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use etherparse::PacketBuilder;
use hostsight::capture::{self, IngestOptions};
use tempfile::tempdir;

fn eth_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 1, 8192)
        .ack(1);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).unwrap();
    buf
}

fn write_pcap(path: &PathBuf, packets: &[Vec<u8>]) {
    let mut f = std::fs::File::create(path).unwrap();
    capture::pcap_over_ip::write_pcap_stream(&mut f, packets).unwrap();
}

#[test]
fn etl_magic_carves_embedded_frame() {
    let dir = tempdir().unwrap();
    let etl_path = dir.path().join("trace.etl");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let frame = eth_tcp(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        4000,
        80,
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\ntest",
    );
    // Direct carve of the bare frame must work
    let direct = capture::carver::carve_bytes(&frame, None, &out, &IngestOptions::default()).unwrap();
    assert!(
        !direct.hosts.is_empty() || !direct.sessions.is_empty() || !direct.files.is_empty(),
        "bare frame summary={}",
        direct.summary()
    );

    let mut blob = b"ElfFile\0".to_vec();
    blob.extend_from_slice(&[0xFFu8; 128]); // high bytes avoid looking like IPv4
    blob.extend_from_slice(&frame);
    std::fs::write(&etl_path, &blob).unwrap();

    let case = capture::ingest_file(&etl_path, &out, &IngestOptions::default()).unwrap();
    assert!(
        case.anomalies.iter().any(|a| a.kind == "etl"),
        "{:?}",
        case.anomalies
    );
    assert!(
        !case.hosts.is_empty() || !case.sessions.is_empty() || !case.files.is_empty(),
        "etl summary={} carved={}",
        case.summary(),
        capture::carver::carve_frames(&blob).len()
    );
}

#[test]
fn packetcache_hspc_magic_stream() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pkt = eth_tcp(
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(5, 6, 7, 8),
        1,
        80,
        b"GET / HTTP/1.0\r\n\r\n",
    );

    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.write_all(capture::packetcache::MAGIC).unwrap();
        capture::pcap_over_ip::write_pcap_stream(&mut sock, &[pkt]).unwrap();
        thread::sleep(Duration::from_millis(30));
    });
    thread::sleep(Duration::from_millis(20));
    let case = capture::packetcache::ingest_connect(
        &addr.to_string(),
        &out,
        &IngestOptions::default(),
        Some(50),
    )
    .unwrap();
    server.join().unwrap();
    assert!(!case.hosts.is_empty() || !case.sessions.is_empty());
}

#[test]
fn irc_and_njrat_and_iec104() {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("x.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let c = Ipv4Addr::new(10, 5, 0, 1);
    let s = Ipv4Addr::new(10, 5, 0, 2);

    let irc = b"PRIVMSG #room :hello hostsight\r\n";
    let nj = b"inf|'|'|victim-pc|'|'|admin|'|'|";
    let iec = vec![0x68, 0x04, 0x01, 0x00, 0x00, 0x00];

    write_pcap(
        &pcap,
        &[
            eth_tcp(c, s, 50000, 6667, irc),
            eth_tcp(c, s, 50001, 5552, nj),
            eth_tcp(c, s, 50002, 2404, &iec),
        ],
    );
    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    assert!(
        case.messages.iter().any(|m| m.protocol == "IRC"),
        "{:?}",
        case.messages
    );
    assert!(
        case.parameters.iter().any(|p| p.source == "njRAT"),
        "{:?}",
        case.parameters
    );
    assert!(
        case.parameters.iter().any(|p| p.source == "IEC-104"),
        "{:?}",
        case.parameters
    );
}

#[test]
fn smb2_read_extracts_file() {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("smb.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    // Minimal SMB2 READ response: NetBIOS length + SMB2 header + READ body
    let file_data = b"SMB2-FILE-BYTES-12345";
    let mut smb = vec![0u8; 64];
    smb[0..4].copy_from_slice(b"\xfeSMB");
    smb[12] = 8; // READ
    smb[13] = 0;
    smb[16] = 1; // response flag
    // READ response structure at offset 64
    let mut body = vec![0u8; 16];
    body[0] = 17;
    body[1] = 0; // structure size
    body[2] = 80; // data offset from SMB2 start (64+16=80)
    body[3] = 0;
    let dlen = file_data.len() as u32;
    body[4..8].copy_from_slice(&dlen.to_le_bytes());
    let mut payload = Vec::new();
    let nb_len = (smb.len() + body.len() + file_data.len()) as u32;
    payload.extend_from_slice(&nb_len.to_be_bytes());
    // fix: NetBIOS is 3-byte length typically; use 4-byte for simplicity matching our peeler
    payload.clear();
    payload.extend_from_slice(&(smb.len() + body.len() + file_data.len() as usize).to_be_bytes());
    // Actually our SMB parser expects either feSMB at 0 or at 4
    payload.clear();
    let total = smb.len() + body.len() + file_data.len();
    payload.extend_from_slice(&(total as u32).to_be_bytes());
    payload.extend_from_slice(&smb);
    payload.extend_from_slice(&body);
    payload.extend_from_slice(file_data);
    // data_offset 80: from start of smb which is at payload[4..]
    // smb starts at index 4 in payload; data at 4+80 = 84
    // We set data_offset=80 meaning offset within smb buffer = 80 = 64+16, correct.

    let frame = eth_tcp(
        Ipv4Addr::new(10, 6, 0, 2),
        Ipv4Addr::new(10, 6, 0, 1),
        445,
        50000,
        &payload,
    );
    write_pcap(&pcap, &[frame]);
    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    assert!(
        case.files.iter().any(|f| f.protocol == "SMB2" && f.size == file_data.len() as u64),
        "files={:?}",
        case.files
    );
}

#[test]
fn erspan_gre_peel_yields_inner_http() {
    // Build: Ethernet + IPv4(proto GRE) + GRE(proto ERSPAN 0x88BE) + 8-byte erspan + inner Ethernet HTTP
    let inner = eth_tcp(
        Ipv4Addr::new(10, 7, 0, 1),
        Ipv4Addr::new(10, 7, 0, 2),
        1,
        80,
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n",
    );
    let mut gre = vec![0x00, 0x00, 0x88, 0xBE]; // flags + ERSPAN ethertype
    gre.extend_from_slice(&[0u8; 8]); // erspan hdr
    gre.extend_from_slice(&inner);

    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4([10, 8, 0, 1], [10, 8, 0, 2], 64);
    // etherparse PacketBuilder may not expose GRE easily — hand-craft IP+GRE
    let mut ip = vec![0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 64, 47, 0x00, 0x00];
    ip.extend_from_slice(&[10, 8, 0, 1, 10, 8, 0, 2]);
    let total = (ip.len() + gre.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    // checksum leave 0
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&gre);

    let dir = tempdir().unwrap();
    let pcap = dir.path().join("erspan.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    write_pcap(&pcap, &[frame]);
    let _ = builder; // silence
    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    assert!(
        !case.hosts.is_empty() || !case.files.is_empty() || !case.sessions.is_empty(),
        "summary={}",
        case.summary()
    );
}

#[test]
fn timezone_custom_cycles() {
    use hostsight::TimezoneMode;
    let mut t = TimezoneMode::Utc;
    t = t.cycle();
    assert!(matches!(t, TimezoneMode::Local));
    t = t.cycle();
    assert!(matches!(t, TimezoneMode::Custom(1)));
    assert!(t.label().contains("+1"));
}

#[test]
fn ingest_frames_and_merge() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let frame = eth_tcp(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        1234,
        80,
        b"GET /ui HTTP/1.0\r\nHost: example.test\r\n\r\n",
    );
    let batch = capture::ingest_frames(&[frame], 0, &out, &IngestOptions::default()).unwrap();
    assert!(!batch.hosts.is_empty() || !batch.sessions.is_empty());
    let mut case = hostsight::case::Case::default();
    case.merge_from(batch);
    assert!(!case.hosts.is_empty() || !case.sessions.is_empty());
}

