//! DNS top-sites whitelist (Alexa-class local list).

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Debug, Default, Clone)]
pub struct DnsWhitelist {
    domains: HashSet<String>,
}

impl DnsWhitelist {
    pub fn builtin() -> Self {
        let mut domains = HashSet::new();
        for d in [
            "google.com",
            "www.google.com",
            "googleapis.com",
            "gstatic.com",
            "cloudflare.com",
            "microsoft.com",
            "office.com",
            "github.com",
            "example.com",
            "apple.com",
            "amazon.com",
            "facebook.com",
            "youtube.com",
        ] {
            domains.insert(d.to_ascii_lowercase());
        }
        Self { domains }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut domains = HashSet::new();
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            domains.insert(t.to_ascii_lowercase());
        }
        Ok(Self { domains })
    }

    pub fn contains(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        if self.domains.contains(&n) {
            return true;
        }
        // suffix match: foo.google.com matches google.com
        for d in &self.domains {
            if n.ends_with(&format!(".{d}")) {
                return true;
            }
        }
        false
    }
}
