//! Post-parse intelligence: enrichment, PIPI labels, browser traces, OS guess.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::Result;
use ipnet::IpNet;

use crate::case::Case;
use crate::enrich::{EnrichConfig, Enrichers};
use crate::fingerprint::{self, DecodeAsMap};

pub fn postprocess(
    case: &mut Case,
    enrich_cfg: &EnrichConfig,
    decode_as: &DecodeAsMap,
    pipi_hints: &HashMap<(IpAddr, u16, IpAddr, u16), String>,
) -> Result<()> {
    let enrichers = Enrichers::load(enrich_cfg)?;
    enrichers.apply(case);
    fingerprint::enrich_hosts_os(case);
    fingerprint::apply_pipi_to_case(case, decode_as, pipi_hints);
    fingerprint::browser::attach_to_case(case);
    Ok(())
}

/// Keep only hosts (and related rows) matching any CIDR in `filters`. Empty = no filter.
pub fn apply_cidr_filter(case: &mut Case, filters: &[IpNet]) {
    if filters.is_empty() {
        return;
    }
    let keep: std::collections::HashSet<IpAddr> = case
        .hosts
        .keys()
        .copied()
        .filter(|ip| filters.iter().any(|n| n.contains(ip)))
        .collect();
    case.hosts.retain(|ip, _| keep.contains(ip));
    case.sessions
        .retain(|s| keep.contains(&s.src) || keep.contains(&s.dst));
    case.dns_records.retain(|d| {
        d.client.map(|c| keep.contains(&c)).unwrap_or(true)
            || d.server.map(|s| keep.contains(&s)).unwrap_or(true)
    });
    case.files.retain(|f| {
        f.source_host.map(|h| keep.contains(&h)).unwrap_or(true)
            || f.dest_host.map(|h| keep.contains(&h)).unwrap_or(true)
    });
}

pub fn parse_cidr_list(raw: &str) -> Result<Vec<IpNet>> {
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        out.push(IpNet::from_str(t)?);
    }
    Ok(out)
}

pub const HOST_COLORS: &[&str] = &["red", "orange", "yellow", "green", "blue", "purple", "gray"];
