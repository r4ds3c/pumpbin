//! Windows ETL ingest (netsh trace / pktmon).
//!
//! Full ETW decoding is complex; we validate ETL magic and carve Ethernet/IP
//! frames from the event blobs (same strategy as Network Packet Carver).

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::capture::{carver, IngestOptions};
use crate::case::Case;

/// True if `data` looks like a Windows ETL / Event Trace Log.
pub fn looks_like_etl(data: &[u8]) -> bool {
    data.starts_with(b"ElfFile\0")
        || data.starts_with(b"LidFile\0")
        || data.starts_with(b"PACE") // older
        || (data.len() >= 4 && &data[0..4] == b"\x45\x6c\x66\x00") // Elf\0
}

pub fn ingest_etl(path: &Path, output_dir: &Path, opts: &IngestOptions) -> Result<Case> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if !looks_like_etl(&data) {
        bail!(
            "{} does not look like an ETL file (expected ElfFile/LidFile header)",
            path.display()
        );
    }
    let mut case = carver::carve_bytes(&data, Some(path), output_dir, opts)?;
    case.anomalies.push(crate::case::Anomaly {
        kind: "etl".into(),
        detail: "ETL ingested via frame carving inside Event Trace Log (not full ETW decode)"
            .into(),
        frame: 0,
    });
    Ok(case)
}
