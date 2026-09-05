//! Offline enrichment: GeoIP, ASN, DNS whitelist, trackers, OSINT hooks.

mod geo;
mod osint;
mod trackers;
mod whitelist;

pub use geo::{AsnDb, GeoDb, GeoResult};
pub use osint::{lookup_all, OsintKind, OsintProvider, OsintQuery, OsintResult};
pub use trackers::is_tracker_or_ad;
pub use whitelist::DnsWhitelist;

use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;

use crate::case::Case;

/// Runtime enrichment configuration (local files only; OSINT is user-initiated).
#[derive(Debug, Clone, Default)]
pub struct EnrichConfig {
    pub geo_db_path: Option<std::path::PathBuf>,
    pub asn_db_path: Option<std::path::PathBuf>,
    pub dns_whitelist_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Default)]
pub struct Enrichers {
    pub geo: GeoDb,
    pub asn: AsnDb,
    pub whitelist: DnsWhitelist,
}

impl Enrichers {
    pub fn load(cfg: &EnrichConfig) -> Result<Self> {
        let mut e = Self {
            geo: GeoDb::builtin(),
            asn: AsnDb::builtin(),
            whitelist: DnsWhitelist::builtin(),
        };
        if let Some(p) = &cfg.geo_db_path {
            e.geo = GeoDb::load(p)?;
        }
        if let Some(p) = &cfg.asn_db_path {
            e.asn = AsnDb::load(p)?;
        }
        if let Some(p) = &cfg.dns_whitelist_path {
            e.whitelist = DnsWhitelist::load(p)?;
        }
        Ok(e)
    }

    /// Apply offline enrichment to an already-parsed case.
    pub fn apply(&self, case: &mut Case) {
        for host in case.hosts.values_mut() {
            if let Some(g) = self.geo.lookup(host.ip) {
                host.country = Some(g.country);
            }
            if let Some(a) = self.asn.lookup(host.ip) {
                host.asn = Some(a);
            }
        }
        for dns in &mut case.dns_records {
            dns.whitelisted = self.whitelist.contains(&dns.query);
            dns.is_tracker = is_tracker_or_ad(&dns.query);
        }
    }
}

pub fn lookup_country(geo: &GeoDb, ip: IpAddr) -> Option<String> {
    geo.lookup(ip).map(|g| g.country)
}

/// Ensure parent dirs exist when writing sample DBs for operators.
pub fn write_sample_dbs(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("geo.csv"),
        "# prefix,country\n8.8.8.0/24,US\n1.1.1.0/24,AU\n93.184.216.0/24,US\n10.0.0.0/8,RFC1918\n",
    )?;
    std::fs::write(
        dir.join("asn.csv"),
        "# prefix,asn\n8.8.8.0/24,AS15169 Google\n1.1.1.0/24,AS13335 Cloudflare\n93.184.216.0/24,AS15133 EdgeCast\n",
    )?;
    std::fs::write(
        dir.join("dns_whitelist.txt"),
        "google.com\nwww.google.com\ncloudflare.com\nmicrosoft.com\ngithub.com\nexample.com\n",
    )?;
    Ok(())
}
