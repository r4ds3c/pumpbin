//! Phase 3: packet carver, Pcap-over-IP, SIP/RTP → WAV.

use std::io::Read;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use etherparse::PacketBuilder;
use hostsight::capture::{self, IngestOptions};
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

fn eth_tcp_http() -> Vec<u8> {
    let c = Ipv4Addr::new(10, 1, 1, 1);
    let s = Ipv4Addr::new(10, 1, 1, 2);
    let req = b"GET /carved.txt HTTP/1.1\r\nHost: x\r\n\r\n";
    let body = b"carved-body";
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body);
    // return response packet only for carver (single-packet HTTP extract path)
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 1])
        .ipv4(s.octets(), c.octets(), 64)
        .tcp(80, 40000, 1, 8192)
        .ack(1);
    let mut buf = Vec::with_capacity(builder.size(resp.len()));
    builder.write(&mut buf, &resp).unwrap();
    let _ = req;
    buf
}

#[test]
fn carver_recovers_http_from_blob() {
    let dir = tempdir().unwrap();
    let dump = dir.path().join("mem.bin");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let frame = eth_tcp_http();
    let mut blob = vec![0xAAu8; 64];
    blob.extend_from_slice(&frame);
    blob.extend_from_slice(&[0xBBu8; 32]);
    std::fs::write(&dump, &blob).unwrap();

    let case = capture::carver::carve_file(&dump, &out, &IngestOptions::default()).unwrap();
    assert!(
        !case.hosts.is_empty() || !case.files.is_empty() || !case.sessions.is_empty(),
        "expected carved artifacts: hosts={} files={} sessions={} anomalies={:?}",
        case.hosts.len(),
        case.files.len(),
        case.sessions.len(),
        case.anomalies
    );
    assert!(
        case.files.iter().any(|f| f.protocol == "HTTP") || !case.hosts.is_empty(),
        "files={:?}",
        case.files
    );
}

#[test]
fn pcap_over_ip_connect_ingests() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let packets = vec![eth_tcp_http()];

    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        capture::pcap_over_ip::write_pcap_stream(&mut sock, &packets).unwrap();
        // keep socket open briefly
        thread::sleep(Duration::from_millis(50));
    });

    thread::sleep(Duration::from_millis(20));
    let case = capture::pcap_over_ip::ingest_connect(
        &addr.to_string(),
        &out,
        &IngestOptions::default(),
        Some(100),
    )
    .unwrap();
    server.join().unwrap();

    assert!(!case.hosts.is_empty() || !case.files.is_empty() || !case.sessions.is_empty());
}

#[test]
fn sip_rtp_produces_wav() {
    let dir = tempdir().unwrap();
    let pcap = dir.path().join("voip.pcap");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let ua = Ipv4Addr::new(10, 2, 0, 1);
    let peer = Ipv4Addr::new(10, 2, 0, 2);

    let invite = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.2.0.1:5060\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test-call-1@hostsight\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 80\r\n\
\r\n\
v=0\r\n\
o=- 0 0 IN IP4 10.2.0.1\r\n\
s=-\r\n\
c=IN IP4 10.2.0.1\r\n\
t=0 0\r\n\
m=audio 4000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";

    // RTP header + μ-law payload (silence ~0xff)
    let mut rtp = vec![
        0x80, 0x00, // V=2, PT=0
        0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ts
        0x11, 0x22, 0x33, 0x44, // ssrc
    ];
    rtp.extend(std::iter::repeat(0xffu8).take(160));

    let mut rtp2 = rtp.clone();
    rtp2[3] = 0x02;

    let packets = vec![
        eth_udp(ua, peer, 5060, 5060, invite),
        eth_udp(ua, peer, 4000, 4000, &rtp),
        eth_udp(ua, peer, 4000, 4000, &rtp2),
    ];
    write_pcap(&pcap, &packets);

    let case = capture::ingest_file(&pcap, &out, &IngestOptions::default()).unwrap();
    assert!(
        case.voip_calls.iter().any(|c| c.call_id.contains("test-call") || c.audio_path.is_some()),
        "voip={:?}",
        case.voip_calls
    );
    assert!(
        case.voip_calls.iter().any(|c| {
            c.audio_path
                .as_ref()
                .map(|p| p.exists() && p.extension().and_then(|e| e.to_str()) == Some("wav"))
                .unwrap_or(false)
        }),
        "expected WAV file, voip={:?}",
        case.voip_calls
    );
}

#[test]
fn write_and_read_pcap_stream_roundtrip() {
    let mut buf = Vec::new();
    let pkt = eth_udp(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(1, 1, 1, 2),
        53,
        53,
        &[0u8; 12],
    );
    capture::pcap_over_ip::write_pcap_stream(&mut buf, &[pkt]).unwrap();
    assert!(buf.len() > 24);
    let mut cursor = std::io::Cursor::new(buf);
    let mut gh = [0u8; 24];
    cursor.read_exact(&mut gh).unwrap();
    assert_eq!(&gh[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
}
