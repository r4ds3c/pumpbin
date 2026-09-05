//! PacketCache-compatible / documented stream ingest.
//!
//! NETRESEC PacketCache is proprietary. HostSight accepts a documented
//! equivalent: optional 4-byte magic `HSPC` followed by a classic PCAP
//! stream (same framing as Pcap-over-IP). Raw PCAP without magic also works.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::capture::{pcap_over_ip, IngestOptions};
use crate::case::Case;

pub const MAGIC: &[u8; 4] = b"HSPC";

pub fn ingest_listen(
    bind: &str,
    output_dir: &Path,
    opts: &IngestOptions,
    max_packets: Option<u64>,
) -> Result<Case> {
    let listener = TcpListener::bind(bind).with_context(|| format!("bind {bind}"))?;
    let (mut stream, _) = listener.accept().context("accept")?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    ingest_stream(&mut stream, output_dir, opts, max_packets)
}

pub fn ingest_connect(
    addr: &str,
    output_dir: &Path,
    opts: &IngestOptions,
    max_packets: Option<u64>,
) -> Result<Case> {
    let mut stream = TcpStream::connect(addr).with_context(|| format!("connect {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    ingest_stream(&mut stream, output_dir, opts, max_packets)
}

fn ingest_stream<R: Read>(
    reader: &mut R,
    output_dir: &Path,
    opts: &IngestOptions,
    max_packets: Option<u64>,
) -> Result<Case> {
    let mut peek = [0u8; 4];
    reader.read_exact(&mut peek).context("read stream header")?;
    if &peek == MAGIC {
        pcap_over_ip::ingest_reader(reader, output_dir, opts, max_packets)
    } else {
        let mut prefixed = PeekReader {
            prefix: peek,
            prefix_pos: 0,
            inner: reader,
        };
        pcap_over_ip::ingest_reader(&mut prefixed, output_dir, opts, max_packets)
    }
}

struct PeekReader<'a, R: Read> {
    prefix: [u8; 4],
    prefix_pos: usize,
    inner: &'a mut R,
}

impl<R: Read> Read for PeekReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.prefix_pos < 4 {
            let n = (4 - self.prefix_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.prefix_pos..self.prefix_pos + n]);
            self.prefix_pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}
