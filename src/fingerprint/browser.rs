//! Browser path reconstruction from cleartext HTTP.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::case::Case;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHop {
    pub client: Option<IpAddr>,
    pub host: String,
    pub path: String,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub method: String,
}

/// Rebuild a browsing trail from HTTP request parameters / known request lines in anomalies.
pub fn build_traces(case: &Case) -> Vec<BrowserHop> {
    let mut hops = Vec::new();

    // From Host + path-like parameters
    let mut hosts: Vec<String> = case
        .hosts
        .values()
        .flat_map(|h| h.hostnames.iter().cloned())
        .collect();
    hosts.sort();
    hosts.dedup();

    // Prefer explicit HTTP query/path parameters and cookie hosts
    for p in &case.parameters {
        if p.source == "HTTP query" || p.source.starts_with("HTTP") {
            // skip pure kv
        }
    }

    // Reconstruct from credentials details (path) + hostnames on same flow — lightweight:
    // Scan parameters named like path from FTP/HTTP isn't enough.
    // Use files with HTTP protocol + dest host hostnames.
    for f in &case.files {
        if f.protocol != "HTTP" && f.protocol != "HTTP/2" {
            continue;
        }
        let host = f
            .source_host
            .and_then(|ip| case.hosts.get(&ip))
            .and_then(|h| h.hostnames.first().cloned())
            .unwrap_or_else(|| {
                f.source_host
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "?".into())
            });
        let ua = f.dest_host.and_then(|ip| {
            case.hosts
                .get(&ip)
                .and_then(|h| h.user_agents.first().cloned())
        });
        hops.push(BrowserHop {
            client: f.dest_host,
            host,
            path: format!("/{}", f.name),
            referer: None,
            user_agent: ua,
            method: "GET".into(),
        });
    }

    // Also fold Referer-like parameters
    for p in &case.parameters {
        if p.name.eq_ignore_ascii_case("referer") || p.name.eq_ignore_ascii_case("referrer") {
            if let Some(last) = hops.last_mut() {
                last.referer = Some(p.value.clone());
            }
        }
    }

    hops
}

pub fn attach_to_case(case: &mut Case) {
    case.browser_traces = build_traces(case);
}

/// Helper used when parsing HTTP requests live — push a hop immediately.
pub fn push_hop(
    case: &mut Case,
    client: IpAddr,
    host_hdr: &str,
    path: &str,
    method: &str,
    referer: Option<&str>,
    ua: Option<&str>,
) {
    case.browser_traces.push(BrowserHop {
        client: Some(client),
        host: host_hdr.to_string(),
        path: path.to_string(),
        referer: referer.map(|s| s.to_string()),
        user_agent: ua.map(|s| s.to_string()),
        method: method.to_string(),
    });
}
