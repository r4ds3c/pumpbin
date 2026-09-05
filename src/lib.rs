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
    SelectHost(IpAddr),
    LiveRefreshDevices,
    LiveDevicesDone(Result<Vec<capture::live::CaptureDevice>, String>),
    LiveSelectDevice(usize),
    LiveStart,
    LiveStop,
    LiveBatchDone(Result<(Case, usize), String>),
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
    pub selected_host: Option<IpAddr>,
    pub keyword_draft: String,
    pub last_capture_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub defang_executables: bool,
    pub timezone: TimezoneMode,
    pub cidr_filter: String,
    pub status: String,
    pub busy: bool,
    pub selected_theme: Theme,
    pub live_devices: Vec<capture::live::CaptureDevice>,
    pub live_device_idx: Option<usize>,
    pub live_running: bool,
    pub live_packets: u64,
    pub live_batches: u64,
}

impl Default for HostSight {
    fn default() -> Self {
        let output_dir = dirs::desktop_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            case: Case::default(),
            selected_tab: Tab::Hosts,
            selected_host: None,
            keyword_draft: String::new(),
            last_capture_path: None,
            output_dir,
            defang_executables: true,
            timezone: TimezoneMode::Utc,
            cidr_filter: String::new(),
            status: "Open a capture or start live sniff.".into(),
            busy: false,
            selected_theme: Theme::CatppuccinMacchiato,
            live_devices: Vec::new(),
            live_device_idx: None,
            live_running: false,
            live_packets: 0,
            live_batches: 0,
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
                if let Some(ip) = self.selected_host {
                    if !self.case.hosts.contains_key(&ip) {
                        self.selected_host = self.case.hosts.keys().next().copied();
                    }
                } else {
                    self.selected_host = self.case.hosts.keys().next().copied();
                }
                self.status = summary;
                Task::none()
            }
            Message::ParseDone(Err(err)) => {
                self.busy = false;
                self.status = format!("Parse failed: {err}");
                message_dialog(err, MessageLevel::Error).map(|_| Message::NoOp)
            }
            Message::ClearCase => {
                if self.live_running {
                    self.status = "Stop live capture before clearing.".into();
                    return Task::none();
                }
                self.case = Case::default();
                self.selected_host = None;
                self.last_capture_path = None;
                self.live_packets = 0;
                self.live_batches = 0;
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
            Message::SelectHost(ip) => {
                self.selected_host = Some(ip);
                self.selected_tab = Tab::Hosts;
                Task::none()
            }
            Message::LiveRefreshDevices => {
                Task::perform(
                    async {
                        std::thread::spawn(|| {
                            capture::live::list_devices().map_err(|e| e.to_string())
                        })
                        .join()
                        .unwrap_or_else(|_| Err("device list thread panicked".into()))
                    },
                    Message::LiveDevicesDone,
                )
            }
            Message::LiveDevicesDone(Ok(devs)) => {
                self.live_devices = devs;
                if self.live_devices.is_empty() {
                    self.live_device_idx = None;
                    self.status = "No capture devices found.".into();
                } else {
                    if self
                        .live_device_idx
                        .map(|i| i >= self.live_devices.len())
                        .unwrap_or(true)
                    {
                        self.live_device_idx = Some(0);
                    }
                    self.status = format!("{} capture device(s) ready.", self.live_devices.len());
                }
                Task::none()
            }
            Message::LiveDevicesDone(Err(err)) => {
                self.live_devices.clear();
                self.live_device_idx = None;
                self.status = err;
                Task::none()
            }
            Message::LiveSelectDevice(idx) => {
                if idx < self.live_devices.len() {
                    self.live_device_idx = Some(idx);
                }
                Task::none()
            }
            Message::LiveStart => {
                if self.live_running || self.busy {
                    return Task::none();
                }
                let Some(idx) = self.live_device_idx else {
                    self.status = "Refresh devices and select an interface first.".into();
                    return Task::none();
                };
                let Some(dev) = self.live_devices.get(idx).cloned() else {
                    self.status = "Invalid capture device.".into();
                    return Task::none();
                };
                self.live_running = true;
                self.status = format!("Live sniffing on {}…", dev.label());
                self.schedule_live_batch(dev.name)
            }
            Message::LiveStop => {
                self.live_running = false;
                self.status = format!(
                    "Live stopped. {} packets in {} batches. {}",
                    self.live_packets,
                    self.live_batches,
                    self.case.summary()
                );
                Task::none()
            }
            Message::LiveBatchDone(Ok((batch, n))) => {
                self.live_packets = self.live_packets.saturating_add(n as u64);
                if n > 0 {
                    self.live_batches = self.live_batches.saturating_add(1);
                    self.case.merge_from(batch);
                    if self.selected_host.is_none() {
                        self.selected_host = self.case.hosts.keys().next().copied();
                    }
                }
                self.status = format!(
                    "Live: {} pkts | {}",
                    self.live_packets,
                    self.case.summary()
                );
                if self.live_running {
                    if let Some(idx) = self.live_device_idx {
                        if let Some(dev) = self.live_devices.get(idx).cloned() {
                            return self.schedule_live_batch(dev.name);
                        }
                    }
                    self.live_running = false;
                }
                Task::none()
            }
            Message::LiveBatchDone(Err(err)) => {
                self.live_running = false;
                self.status = format!("Live capture error: {err}");
                message_dialog(err, MessageLevel::Error).map(|_| Message::NoOp)
            }
            Message::NoOp => Task::none(),
        }
    }

    fn schedule_live_batch(&self, device: String) -> Task<Message> {
        let output_dir = self.output_dir.clone();
        let opts = self.ingest_opts();
        let frame_offset = self.live_packets;
        Task::perform(
            async move {
                std::thread::spawn(move || {
                    let frames =
                        capture::live::sniff_frames(&device, 48, 250, 750).map_err(|e| e.to_string())?;
                    let n = frames.len();
                    if n == 0 {
                        return Ok((Case::default(), 0));
                    }
                    let case = capture::ingest_frames(&frames, frame_offset, &output_dir, &opts)
                        .map_err(|e| e.to_string())?;
                    Ok((case, n))
                })
                .join()
                .unwrap_or_else(|_| Err("live batch thread panicked".into()))
            },
            Message::LiveBatchDone,
        )
    }

    pub fn view(&self) -> Element<'_, Message> {
        ui::view(self)
    }
}
