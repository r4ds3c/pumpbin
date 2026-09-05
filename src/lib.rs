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
pub mod proto;
pub mod reassembly;
pub mod style;
pub mod ui;
pub mod utils;

use std::path::PathBuf;

use iced::{Element, Task, Theme};
use rfd::{AsyncFileDialog, MessageLevel};

use crate::capture::IngestOptions;
use crate::case::Case;
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
    NoOp,
}

#[derive(Debug)]
pub struct HostSight {
    pub case: Case,
    pub selected_tab: Tab,
    pub keyword_draft: String,
    pub last_capture_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub defang_executables: bool,
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
            Message::NoOp => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        ui::view(self)
    }
}
