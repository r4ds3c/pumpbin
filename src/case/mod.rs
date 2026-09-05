//! Case model: host-centric aggregation of forensic artifacts.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Case {
    pub source_path: Option<PathBuf>,
    pub hosts: BTreeMap<IpAddr, Host>,
    pub sessions: Vec<Session>,
    pub dns_records: Vec<DnsRecord>,
    pub files: Vec<ExtractedFile>,
    pub credentials: Vec<Credential>,
    pub parameters: Vec<Parameter>,
    pub keywords: Vec<KeywordHit>,
    pub anomalies: Vec<Anomaly>,
    pub messages: Vec<MessageArtifact>,
    pub images: Vec<ExtractedFile>,
    pub voip_calls: Vec<VoipCall>,
    pub tls_handshakes: Vec<TlsHandshake>,
    pub browser_traces: Vec<crate::fingerprint::browser::BrowserHop>,
}

impl Case {
    pub fn summary(&self) -> String {
        format!(
            "Hosts: {}  Sessions: {}  DNS: {}  Files: {}  Creds: {}  TLS: {}  Msgs: {}",
            self.hosts.len(),
            self.sessions.len(),
            self.dns_records.len(),
            self.files.len(),
            self.credentials.len(),
            self.tls_handshakes.len(),
            self.messages.len()
        )
    }

    pub fn ensure_host(&mut self, ip: IpAddr) -> &mut Host {
        self.hosts.entry(ip).or_insert_with(|| Host::new(ip))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub oui_vendor: Option<String>,
    pub hostnames: Vec<String>,
    pub user_agents: Vec<String>,
    pub open_ports: Vec<u16>,
    pub os_guess: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub color: Option<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

impl Host {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            mac: None,
            oui_vendor: None,
            hostnames: Vec::new(),
            user_agents: Vec::new(),
            open_ports: Vec::new(),
            os_guess: None,
            country: None,
            asn: None,
            color: None,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub proto: String,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets: u64,
    pub start_ts: Option<f64>,
    pub end_ts: Option<f64>,
    /// Port-independent protocol identification.
    pub pipi: Option<String>,
    /// Application protocol (PIPI or decode-as).
    pub app_proto: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub query: String,
    pub qtype: String,
    pub answers: Vec<String>,
    pub client: Option<IpAddr>,
    pub server: Option<IpAddr>,
    pub frame: u64,
    pub whitelisted: bool,
    pub is_tracker: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub source_host: Option<IpAddr>,
    pub dest_host: Option<IpAddr>,
    pub protocol: String,
    pub content_type: Option<String>,
    pub is_image: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub protocol: String,
    pub username: String,
    pub secret: String,
    pub host: Option<IpAddr>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub source: String,
    pub host: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordHit {
    pub keyword: String,
    pub context: String,
    pub frame: u64,
    pub session: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: String,
    pub detail: String,
    pub frame: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageArtifact {
    pub protocol: String,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub body_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoipCall {
    pub call_id: String,
    pub from: String,
    pub to: String,
    pub codec: String,
    pub audio_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshake {
    pub frame: u64,
    pub client: IpAddr,
    pub server: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja4: Option<String>,
    pub version: Option<String>,
    pub role: String,
}
