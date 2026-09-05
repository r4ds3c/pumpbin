//! Simple offline prefix→country / ASN CSV databases (no MaxMind dependency).

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct GeoResult {
    pub country: String,
}

#[derive(Debug, Clone)]
struct PrefixEntry {
    network: ipnet::IpNet,
    value: String,
}

#[derive(Debug, Default)]
pub struct GeoDb {
    entries: Vec<PrefixEntry>,
}

#[derive(Debug, Default)]
pub struct AsnDb {
    entries: Vec<PrefixEntry>,
}

impl GeoDb {
    pub fn builtin() -> Self {
        Self::from_lines(
            [
                "10.0.0.0/8,RFC1918",
                "172.16.0.0/12,RFC1918",
                "192.168.0.0/16,RFC1918",
                "127.0.0.0/8,Local",
                "8.8.8.0/24,US",
                "1.1.1.0/24,AU",
                "93.184.216.0/24,US",
            ]
            .into_iter()
            .map(String::from),
        )
    }

    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        Ok(Self::from_lines(
            BufReader::new(f)
                .lines()
                .map_while(Result::ok)
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')),
        ))
    }

    fn from_lines(lines: impl Iterator<Item = String>) -> Self {
        let mut entries = Vec::new();
        for line in lines {
            if let Some((pfx, country)) = line.split_once(',') {
                if let Ok(network) = ipnet::IpNet::from_str(pfx.trim()) {
                    entries.push(PrefixEntry {
                        network,
                        value: country.trim().to_string(),
                    });
                }
            }
        }
        // Longest prefix first
        entries.sort_by_key(|e| std::cmp::Reverse(e.network.prefix_len()));
        Self { entries }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoResult> {
        self.entries
            .iter()
            .find(|e| e.network.contains(&ip))
            .map(|e| GeoResult {
                country: e.value.clone(),
            })
    }
}

impl AsnDb {
    pub fn builtin() -> Self {
        Self {
            entries: GeoDb::from_lines(
                [
                    "8.8.8.0/24,AS15169 Google",
                    "1.1.1.0/24,AS13335 Cloudflare",
                    "93.184.216.0/24,AS15133 EdgeCast",
                ]
                .into_iter()
                .map(String::from),
            )
            .entries,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        Ok(Self {
            entries: GeoDb::load(path)?.entries,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.entries
            .iter()
            .find(|e| e.network.contains(&ip))
            .map(|e| e.value.clone())
    }
}
