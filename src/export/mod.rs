//! Case export: CSV / XML / CASE / JSON-LD (Phase 4; JSON MVP).

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::case::Case;

pub fn export_json(case: &Case, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(case).context("serialize case")?;
    let mut f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

pub fn export_hosts_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "ip,hostnames,user_agents,open_ports,bytes_sent,bytes_recv")?;
    for host in case.hosts.values() {
        writeln!(
            f,
            "{},\"{}\",\"{}\",\"{}\",{},{}",
            host.ip,
            host.hostnames.join(";"),
            host.user_agents.join(";"),
            host.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(";"),
            host.bytes_sent,
            host.bytes_recv
        )?;
    }
    Ok(())
}
