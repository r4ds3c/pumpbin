//! Pcap-over-IP: accept a TCP stream of classic PCAP records (listen or connect).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::capture::{IngestOptions, KeywordPattern};
use crate::case::Case;
use crate::decode::{self, DecodeState};
use crate::reassembly::SessionTracker;

/// Connect to a Pcap-over-IP server and ingest until EOF or `max_packets`.
pub fn ingest_connect(
    addr: &str,
    output_dir: &Path,
    opts: &IngestOptions,
    max_packets: Option<u64>,
) -> Result<Case> {
    let mut stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("resolve {addr}"))?,
        Duration::from_secs(10),
    )
    .with_context(|| format!("connect {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    ingest_reader(&mut stream, output_dir, opts, max_packets)
}

/// Listen once, accept one client, ingest PCAP stream.
pub fn ingest_listen(
    bind: &str,
    output_dir: &Path,
    opts: &IngestOptions,
    max_packets: Option<u64>,
) -> Result<Case> {
    let listener = TcpListener::bind(bind).with_context(|| format!("bind {bind}"))?;
    listener.set_nonblocking(false)?;
    let (mut stream, peer) = listener.accept().context("accept")?;
    let _ = peer;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    ingest_reader(&mut stream, output_dir, opts, max_packets)
}

/// Ingest classic PCAP records from any `Read` stream.
pub fn ingest_reader<R: Read>(
    reader: &mut R,
    output_dir: &Path,
    opts: &IngestOptions,
    max_packets: Option<u64>,
) -> Result<Case> {
    let mut case = Case::default();
    std::fs::create_dir_all(output_dir)?;
    let mut tracker = SessionTracker::new();
    let mut state = DecodeState::new();
    let keywords = crate::capture::parse_keywords_pub(&opts.keywords);

    // Global header 24 bytes
    let mut gh = [0u8; 24];
    reader.read_exact(&mut gh).context("pcap global header")?;
    let magic = u32::from_le_bytes(gh[0..4].try_into().unwrap());
    let swapped = match magic {
        0xa1b2c3d4 | 0xa1b23c4d => false,
        0xd4c3b2a1 | 0x4d3cb2a1 => true,
        _ => return Err(anyhow!("not a PCAP stream (bad magic {magic:#x})")),
    };

    let mut frame = 0u64;
    loop {
        if max_packets.is_some_and(|m| frame >= m) {
            break;
        }
        let mut ph = [0u8; 16];
        match reader.read_exact(&mut ph) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let (ts_sec, incl_len) = if swapped {
            (
                u32::from_be_bytes(ph[0..4].try_into().unwrap()),
                u32::from_be_bytes(ph[8..12].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(ph[0..4].try_into().unwrap()),
                u32::from_le_bytes(ph[8..12].try_into().unwrap()),
            )
        };
        if incl_len > 16_000_000 {
            return Err(anyhow!("pcap record too large: {incl_len}"));
        }
        let mut data = vec![0u8; incl_len as usize];
        reader.read_exact(&mut data)?;
        frame += 1;
        decode::process_frame(
            &mut case,
            &mut tracker,
            &mut state,
            output_dir,
            opts.defang_executables,
            &keywords,
            frame,
            ts_sec as f64,
            &data,
        )?;
    }

    case.sessions = tracker.into_sessions();
    crate::decode::finalize(&mut case, &mut state, output_dir)?;
    crate::capture::finalize_ingest(&mut case, opts, &state)?;
    Ok(case)
}

/// Write a classic PCAP (little-endian) to a writer — used by tests / streaming out.
pub fn write_pcap_stream<W: Write>(writer: &mut W, packets: &[Vec<u8>]) -> Result<()> {
    writer.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ])?;
    for (i, pkt) in packets.iter().enumerate() {
        let ts = (i as u32).to_le_bytes();
        let incl = (pkt.len() as u32).to_le_bytes();
        writer.write_all(&ts)?;
        writer.write_all(&[0; 4])?;
        writer.write_all(&incl)?;
        writer.write_all(&incl)?;
        writer.write_all(pkt)?;
    }
    Ok(())
}

// silence unused import in some builds
#[allow(dead_code)]
fn _kw(_: &[KeywordPattern]) {}
