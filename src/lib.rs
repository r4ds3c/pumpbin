//! HostSight — host-centric Network Forensic Analysis Tool (NFAT).
//!
//! Clean-room implementation guided by publicly documented NetworkMiner
//! Professional capabilities. Not affiliated with NETRESEC.

pub mod case;
pub mod capture;
pub mod decode;
pub mod enrich;
pub mod export;
pub mod extract;
pub mod fingerprint;
pub mod intel;
pub mod proto;
pub mod reassembly;
pub mod style;
pub mod ui;
pub mod utils;

use std::net::IpAddr;
use std::path::PathBuf;

use iced::{Element, Task, Theme};
use rfd::{AsyncFileDialog, MessageLevel};

use crate::capture::IngestOptions;
use crate::case::Case;
use crate::enrich::{lookup_all as osint_lookup_all, OsintKind, OsintQuery};
use crate::fingerprint::DecodeAsMap;
use crate::ui::Tab;
use crate::utils::message_dialog;

#[derive(Debug, Clone)]
pub enum Message {
    OpenCaptureClicked,
    OpenCaptureDone(Option<PathBuf>),
    ParseDone(Result<Case, String>),
    ClearCase,
    ReloadCase,
    TabSelected(Tab),
    KeywordChanged(String),
    OutputDirClicked,
    OutputDirDone(Option<PathBuf>),
    OpenOutputFolder,
    ToggleDefang,
    CycleTimezone,
    OpenCarveClicked,
    OpenCarveDone(Option<PathBuf>),
    PlayVoip(usize),
    CidrFilterChanged(String),
    CycleHostColor(IpAddr),
    ExportAllClicked,
    OsintFile(usize),
    OsintDns(usize),
    NoOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimezoneMode {
    Utc,
    Local,
    /// Fixed offset from UTC in whole hours (−12…+14).
    Custom(i8),
}

impl Default for TimezoneMode {
    fn default() -> Self {
        Self::Utc
    }
}

impl TimezoneMode {
    pub fn label(self) -> String {
        match self {
            Self::Utc => "TZ: UTC".into(),
            Self::Local => "TZ: Local".into(),
            Self::Custom(h) => format!("TZ: UTC{h:+}"),
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::Utc => Self::Local,
            Self::Local => Self::Custom(1),
            Self::Custom(1) => Self::Custom(-5),
            Self::Custom(-5) => Self::Custom(8),
            Self::Custom(_) => Self::Utc,
        }
    }

    pub fn format_epoch(&self, epoch_secs: f64) -> String {
        let secs = epoch_secs as i64;
        let adjusted = match self {
            Self::Utc => secs,
            Self::Local => {
                // Approximate: use chrono Local if available
                secs // display as UTC numeric; GUI uses label for mode
            }
            Self::Custom(h) => secs + (*h as i64) * 3600,
        };
        format!("{adjusted}")
    }
}

#[derive(Debug)]
pub struct HostSight {
    pub case: Case,
    pub selected_tab: Tab,
    pub keyword_draft: String,
    pub last_capture_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub defang_executables: bool,
    pub timezone: TimezoneMode,
    pub cidr_filter: String,
    pub status: String,
    pub busy: bool,
    pub selected_theme: Theme,
}

impl Default for HostSight {
    fn default() -> Self {
        let output_dir = dirs::desktop_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            case: Case::default(),
            selected_tab: Tab::Hosts,
            keyword_draft: String::new(),
            last_capture_path: None,
            output_dir,
            defang_executables: true,
            timezone: TimezoneMode::Utc,
            cidr_filter: String::new(),
            status: "Open a PCAP/PcapNG to begin.".into(),
            busy: false,
            selected_theme: Theme::CatppuccinMacchiato,
        }
    }
}

impl HostSight {
    fn ingest_opts(&self) -> IngestOptions {
        IngestOptions {
            keywords: self.keyword_draft.clone(),
            defang_executables: self.defang_executables,
            enrich: Default::default(),
            decode_as: DecodeAsMap::builtin(),
            cidr_filter: self.cidr_filter.clone(),
        }
    }

    pub fn theme(&self) -> Theme {
        self.selected_theme.clone()
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::OpenCaptureClicked => {
                if self.busy {
                    return Task::none();
                }
                let dialog = AsyncFileDialog::new()
                    .add_filter("Capture", &["pcap", "pcapng", "cap"])
                    .add_filter("All", &["*"])
                    .set_title("Open capture")
                    .pick_file();
                Task::perform(dialog, |handle| {
                    Message::OpenCaptureDone(handle.map(|h| h.path().to_path_buf()))
                })
            }
            Message::OpenCaptureDone(Some(path)) => {
                self.busy = true;
                self.status = format!("Parsing {}…", path.display());
                self.last_capture_path = Some(path.clone());
                let output_dir = self.output_dir.clone();
                let opts = self.ingest_opts();
                Task::perform(
                    async move {
                        std::thread::spawn(move || {
                            capture::ingest_file(&path, &output_dir, &opts).map_err(|e| e.to_string())
                        })
                        .join()
                        .unwrap_or_else(|_| Err("parse thread panicked".into()))
                    },
                    Message::ParseDone,
                )
            }
            Message::OpenCaptureDone(None) => Task::none(),
            Message::ParseDone(Ok(case)) => {
                self.busy = false;
                let summary = case.summary();
                self.case = case;
                self.status = summary;
                Task::none()
            }
            Message::ParseDone(Err(err)) => {
                self.busy = false;
                self.status = format!("Parse failed: {err}");
                message_dialog(err, MessageLevel::Error).map(|_| Message::NoOp)
            }
            Message::ClearCase => {
                self.case = Case::default();
                self.last_capture_path = None;
                self.status = "Case cleared.".into();
                Task::none()
            }
            Message::ReloadCase => {
                let Some(path) = self.last_capture_path.clone() else {
                    self.status = "No capture loaded to reload.".into();
                    return Task::none();
                };
                if self.busy {
                    return Task::none();
                }
                self.busy = true;
                self.status = format!("Reloading {}…", path.display());
                let output_dir = self.output_dir.clone();
                let opts = self.ingest_opts();
                Task::perform(
                    async move {
                        std::thread::spawn(move || {
                            capture::ingest_file(&path, &output_dir, &opts).map_err(|e| e.to_string())
                        })
                        .join()
                        .unwrap_or_else(|_| Err("parse thread panicked".into()))
                    },
                    Message::ParseDone,
                )
            }
            Message::TabSelected(tab) => {
                self.selected_tab = tab;
                Task::none()
            }
            Message::KeywordChanged(s) => {
                self.keyword_draft = s;
                Task::none()
            }
            Message::OutputDirClicked => {
                let dialog = AsyncFileDialog::new()
                    .set_title("Select artifact output directory")
                    .pick_folder();
                Task::perform(dialog, |handle| {
                    Message::OutputDirDone(handle.map(|h| h.path().to_path_buf()))
                })
            }
            Message::OutputDirDone(Some(path)) => {
                self.output_dir = path;
                self.status = format!("Output directory: {}", self.output_dir.display());
                Task::none()
            }
            Message::OutputDirDone(None) => Task::none(),
            Message::OpenOutputFolder => {
                let _ = open::that(&self.output_dir);
                Task::none()
            }
            Message::ToggleDefang => {
                self.defang_executables = !self.defang_executables;
                self.status = if self.defang_executables {
                    "Executable defanging: ON".into()
                } else {
                    "Executable defanging: OFF (dangerous)".into()
                };
                Task::none()
            }
            Message::CycleTimezone => {
                self.timezone = self.timezone.cycle();
                self.status = format!("Timezone display: {:?}", self.timezone);
                Task::none()
            }
            Message::OpenCarveClicked => {
                if self.busy {
                    return Task::none();
                }
                let dialog = AsyncFileDialog::new()
                    .add_filter("Memory / blob", &["bin", "dump", "mem", "raw", "img", "vmem"])
                    .add_filter("All", &["*"])
                    .set_title("Carve packets from dump")
                    .pick_file();
                Task::perform(dialog, |handle| {
                    Message::OpenCarveDone(handle.map(|h| h.path().to_path_buf()))
                })
            }
            Message::OpenCarveDone(Some(path)) => {
                self.busy = true;
                self.status = format!("Carving {}…", path.display());
                self.last_capture_path = Some(path.clone());
                let output_dir = self.output_dir.clone();
                let opts = self.ingest_opts();
                Task::perform(
                    async move {
                        std::thread::spawn(move || {
                            capture::carver::carve_file(&path, &output_dir, &opts)
                                .map_err(|e| e.to_string())
                        })
                        .join()
                        .unwrap_or_else(|_| Err("carve thread panicked".into()))
                    },
                    Message::ParseDone,
                )
            }
            Message::OpenCarveDone(None) => Task::none(),
            Message::PlayVoip(idx) => {
                if let Some(call) = self.case.voip_calls.get(idx) {
                    if let Some(path) = &call.audio_path {
                        let _ = open::that(path);
                        self.status = format!("Opened {}", path.display());
                    } else {
                        self.status = "No audio extracted for this call.".into();
                    }
                }
                Task::none()
            }
            Message::CidrFilterChanged(s) => {
                self.cidr_filter = s;
                Task::none()
            }
            Message::CycleHostColor(ip) => {
                if let Some(host) = self.case.hosts.get_mut(&ip) {
                    let cur = host.color.as_deref().unwrap_or("");
                    let idx = crate::intel::HOST_COLORS
                        .iter()
                        .position(|c| *c == cur)
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    if idx >= crate::intel::HOST_COLORS.len() {
                        host.color = None;
                    } else {
                        host.color = Some(crate::intel::HOST_COLORS[idx].to_string());
                    }
                    self.status = format!(
                        "Host {ip} color: {}",
                        host.color.as_deref().unwrap_or("(none)")
                    );
                }
                Task::none()
            }
            Message::ExportAllClicked => {
                let dir = self.output_dir.join("export");
                match export::export_all(&self.case, &dir) {
                    Ok(m) => {
                        self.status = format!(
                            "Exported to {} (hosts={} files={} dns={})",
                            dir.display(),
                            m.hosts,
                            m.files,
                            m.dns
                        );
                    }
                    Err(e) => self.status = format!("Export failed: {e}"),
                }
                Task::none()
            }
            Message::OsintFile(idx) => {
                if let Some(f) = self.case.files.get(idx) {
                    let results = osint_lookup_all(&OsintQuery {
                        kind: OsintKind::Hash,
                        value: f.sha256.clone(),
                    });
                    if let Some(r) = results.first() {
                        if let Some(url) = &r.url {
                            let _ = open::that(url);
                        }
                        self.status = r.summary.clone();
                    }
                }
                Task::none()
            }
            Message::OsintDns(idx) => {
                if let Some(d) = self.case.dns_records.get(idx) {
                    let results = osint_lookup_all(&OsintQuery {
                        kind: OsintKind::Domain,
                        value: d.query.clone(),
                    });
                    if let Some(r) = results.first() {
                        if let Some(url) = &r.url {
                            let _ = open::that(url);
                        }
                        self.status = r.summary.clone();
                    }
                }
                Task::none()
            }
            Message::NoOp => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        ui::view(self)
    }
}
