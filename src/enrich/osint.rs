//! Pluggable OSINT lookups (hash / IP / domain / URL). Offline-first; network is optional.

use std::process::Command;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsintKind {
    Hash,
    Ip,
    Domain,
    Url,
}

#[derive(Debug, Clone)]
pub struct OsintQuery {
    pub kind: OsintKind,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct OsintResult {
    pub provider: String,
    pub summary: String,
    pub url: Option<String>,
}

pub trait OsintProvider: Send + Sync {
    fn name(&self) -> &str;
    fn lookup(&self, q: &OsintQuery) -> Result<OsintResult>;
}

/// Builds public investigation URLs without calling APIs (no keys required).
#[derive(Debug, Default)]
pub struct UrlOnlyProvider;

impl OsintProvider for UrlOnlyProvider {
    fn name(&self) -> &str {
        "public-urls"
    }

    fn lookup(&self, q: &OsintQuery) -> Result<OsintResult> {
        let (summary, url) = match q.kind {
            OsintKind::Hash => (
                format!("VirusTotal / MalwareBazaar search for {}", q.value),
                Some(format!("https://www.virustotal.com/gui/search/{}", q.value)),
            ),
            OsintKind::Ip => (
                format!("IP reputation / whois links for {}", q.value),
                Some(format!("https://www.virustotal.com/gui/ip-address/{}", q.value)),
            ),
            OsintKind::Domain => (
                format!("Domain investigation for {}", q.value),
                Some(format!("https://www.virustotal.com/gui/domain/{}", q.value)),
            ),
            OsintKind::Url => (
                format!("URL investigation for {}", q.value),
                Some(format!(
                    "https://www.virustotal.com/gui/search/{}",
                    urlencoding_minimal(&q.value)
                )),
            ),
        };
        Ok(OsintResult {
            provider: self.name().into(),
            summary,
            url,
        })
    }
}

/// Optional shell-out provider: `HOSTSIGHT_OSINT_CMD` with `{kind}` and `{value}` placeholders.
#[derive(Debug)]
pub struct EnvCmdProvider {
    pub template: String,
}

impl OsintProvider for EnvCmdProvider {
    fn name(&self) -> &str {
        "env-cmd"
    }

    fn lookup(&self, q: &OsintQuery) -> Result<OsintResult> {
        let kind = match q.kind {
            OsintKind::Hash => "hash",
            OsintKind::Ip => "ip",
            OsintKind::Domain => "domain",
            OsintKind::Url => "url",
        };
        let cmd = self
            .template
            .replace("{kind}", kind)
            .replace("{value}", &q.value);
        #[cfg(windows)]
        let output = Command::new("cmd").args(["/C", &cmd]).output()?;
        #[cfg(not(windows))]
        let output = Command::new("sh").args(["-c", &cmd]).output()?;
        if !output.status.success() {
            bail!("osint command failed: {}", output.status);
        }
        let summary = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(OsintResult {
            provider: self.name().into(),
            summary,
            url: None,
        })
    }
}

pub fn default_providers() -> Vec<Box<dyn OsintProvider>> {
    let mut v: Vec<Box<dyn OsintProvider>> = vec![Box::new(UrlOnlyProvider)];
    if let Ok(t) = std::env::var("HOSTSIGHT_OSINT_CMD") {
        if !t.is_empty() {
            v.push(Box::new(EnvCmdProvider { template: t }));
        }
    }
    v
}

pub fn lookup_all(q: &OsintQuery) -> Vec<OsintResult> {
    default_providers()
        .iter()
        .filter_map(|p| p.lookup(q).ok())
        .collect()
}

fn urlencoding_minimal(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}
