//! iced UI: NetworkMiner-style host-centric tabs.

use iced::{
    alignment::Vertical,
    widget::{button, column, container, row, scrollable, text, text_input, Column, Row, Space},
    Element, Length,
};

use crate::style;
use crate::{HostSight, Message};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Hosts,
    Files,
    Images,
    Messages,
    Credentials,
    Parameters,
    Dns,
    Sessions,
    Keywords,
    Anomalies,
    Voip,
}

impl Tab {
    pub const ALL: [Tab; 11] = [
        Tab::Hosts,
        Tab::Files,
        Tab::Images,
        Tab::Messages,
        Tab::Credentials,
        Tab::Parameters,
        Tab::Dns,
        Tab::Sessions,
        Tab::Keywords,
        Tab::Anomalies,
        Tab::Voip,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Hosts => "Hosts",
            Tab::Files => "Files",
            Tab::Images => "Images",
            Tab::Messages => "Messages",
            Tab::Credentials => "Credentials",
            Tab::Parameters => "Parameters",
            Tab::Dns => "DNS",
            Tab::Sessions => "Sessions",
            Tab::Keywords => "Keywords",
            Tab::Anomalies => "Anomalies",
            Tab::Voip => "VoIP",
        }
    }
}

pub fn view(app: &HostSight) -> Element<'_, Message> {
    let toolbar = row![
        button(text("Open capture")).on_press(Message::OpenCaptureClicked),
        button(text("Reload")).on_press(Message::ReloadCase),
        button(text("Clear")).on_press(Message::ClearCase),
        Space::with_width(12),
        button(text("Output dir")).on_press(Message::OutputDirClicked),
        button(text("Open output")).on_press(Message::OpenOutputFolder),
        button(text(if app.defang_executables {
            "Defang: ON"
        } else {
            "Defang: OFF"
        }))
        .on_press(Message::ToggleDefang),
        Space::with_width(Length::Fill),
        text(if app.busy { "Working…" } else { "Ready" }).size(12),
    ]
    .spacing(8)
    .align_y(Vertical::Center)
    .padding(8);

    let tabs = Tab::ALL.iter().fold(Row::new().spacing(4), |row, tab| {
        let label = text(tab.label()).size(12);
        let btn = if *tab == app.selected_tab {
            button(label).style(style::button::selected)
        } else {
            button(label).style(style::button::unselected)
        }
        .on_press(Message::TabSelected(*tab));
        row.push(btn)
    });

    let body = match app.selected_tab {
        Tab::Hosts => hosts_view(app),
        Tab::Files => files_view(app),
        Tab::Images => images_view(app),
        Tab::Messages => messages_view(app),
        Tab::Credentials => credentials_view(app),
        Tab::Parameters => parameters_view(app),
        Tab::Dns => dns_view(app),
        Tab::Sessions => sessions_view(app),
        Tab::Keywords => keywords_view(app),
        Tab::Anomalies => anomalies_view(app),
        Tab::Voip => voip_view(app),
    };

    let status = container(text(&app.status).size(12))
        .padding(8)
        .width(Length::Fill);

    column![toolbar, tabs.padding([0, 8]), body, status]
        .spacing(4)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn panel<'a>(title: &'a str, rows: Column<'a, Message>) -> Element<'a, Message> {
    container(
        column![
            text(title).size(16),
            scrollable(rows.spacing(2).padding(4)).height(Length::Fill)
        ]
        .spacing(8)
        .padding(8),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn hosts_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.hosts.is_empty() {
        col = col.push(text("No hosts yet. Open a capture.").size(13));
    }
    for host in app.case.hosts.values() {
        let tls: Vec<_> = app
            .case
            .tls_handshakes
            .iter()
            .filter(|t| t.client == host.ip || t.server == host.ip)
            .filter_map(|t| t.sni.as_ref().or(t.ja3.as_ref()).or(t.ja3s.as_ref()))
            .take(3)
            .cloned()
            .collect();
        let line = format!(
            "{}  ports:{:?}  hostnames:[{}]  UA:[{}]  TLS:[{}]  ↑{} ↓{}",
            host.ip,
            host.open_ports,
            host.hostnames.join(", "),
            host.user_agents.join(", "),
            tls.join(", "),
            host.bytes_sent,
            host.bytes_recv
        );
        col = col.push(text(line).size(12));
    }
    panel("Hosts", col)
}

fn files_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.files.is_empty() {
        col = col.push(text("No extracted files.").size(13));
    }
    for f in &app.case.files {
        col = col.push(
            text(format!(
                "{}  {} B  {}  sha256:{}…",
                f.name,
                f.size,
                f.protocol,
                &f.sha256[..16.min(f.sha256.len())]
            ))
            .size(12),
        );
    }
    if !app.case.tls_handshakes.is_empty() {
        col = col.push(text("--- TLS handshakes ---").size(12));
        for t in &app.case.tls_handshakes {
            col = col.push(
                text(format!(
                    "#{} {}→{} SNI:{:?} JA3:{:?} JA3S:{:?} JA4:{:?}",
                    t.frame, t.client, t.server, t.sni, t.ja3, t.ja3s, t.ja4
                ))
                .size(11),
            );
        }
    }
    panel("Files", col)
}

fn images_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.images.is_empty() {
        col = col.push(text("No images extracted.").size(13));
    }
    for f in &app.case.images {
        col = col.push(text(format!("{}  ({})", f.name, f.path.display())).size(12));
    }
    panel("Images", col)
}

fn messages_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.messages.is_empty() {
        col = col.push(text("No messages (SMTP/IMAP/POP3/IRC/SIP) yet.").size(13));
    }
    for m in &app.case.messages {
        col = col.push(
            text(format!(
                "[{}] {} → {} | {}",
                m.protocol, m.from, m.to, m.subject
            ))
            .size(12),
        );
    }
    panel("Messages", col)
}

fn credentials_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.credentials.is_empty() {
        col = col.push(text("No credentials found.").size(13));
    }
    for c in &app.case.credentials {
        col = col.push(
            text(format!(
                "[{}] {} / {}  ({})",
                c.protocol, c.username, c.secret, c.details
            ))
            .size(12),
        );
    }
    panel("Credentials", col)
}

fn parameters_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.parameters.is_empty() {
        col = col.push(text("No parameters.").size(13));
    }
    for p in &app.case.parameters {
        col = col.push(
            text(format!(
                "{} = {}  [{}]",
                p.name, p.value, p.source
            ))
            .size(12),
        );
    }
    panel("Parameters", col)
}

fn dns_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.dns_records.is_empty() {
        col = col.push(text("No DNS records.").size(13));
    }
    for d in &app.case.dns_records {
        col = col.push(
            text(format!(
                "#{}  {} {} → [{}]",
                d.frame,
                d.qtype,
                d.query,
                d.answers.join(", ")
            ))
            .size(12),
        );
    }
    panel("DNS", col)
}

fn sessions_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.sessions.is_empty() {
        col = col.push(text("No sessions.").size(13));
    }
    for s in &app.case.sessions {
        col = col.push(
            text(format!(
                "{}  {}:{} ↔ {}:{}  pkts:{}  bytes:{}/{}",
                s.proto, s.src, s.sport, s.dst, s.dport, s.packets, s.bytes_a_to_b, s.bytes_b_to_a
            ))
            .size(12),
        );
    }
    panel("Sessions", col)
}

fn keywords_view(app: &HostSight) -> Element<'_, Message> {
    let input = text_input(
        "Keywords (one per line; 0x… for hex). Reload case to re-scan.",
        &app.keyword_draft,
    )
    .on_input(Message::KeywordChanged);

    let mut hits = Column::new();
    if app.case.keywords.is_empty() {
        hits = hits.push(text("No keyword hits. Set keywords and Reload.").size(13));
    }
    for h in &app.case.keywords {
        hits = hits.push(
            text(format!(
                "#{} [{}] {} | {}",
                h.frame, h.session, h.keyword, h.context
            ))
            .size(12),
        );
    }

    container(
        column![
            text("Keywords").size(16),
            input,
            scrollable(hits).height(Length::Fill)
        ]
        .spacing(8)
        .padding(8),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn anomalies_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.anomalies.is_empty() {
        col = col.push(text("No anomalies recorded.").size(13));
    }
    for a in &app.case.anomalies {
        col = col.push(text(format!("[{}] {}", a.kind, a.detail)).size(12));
    }
    panel("Anomalies", col)
}

fn voip_view(app: &HostSight) -> Element<'_, Message> {
    let mut col = Column::new();
    if app.case.voip_calls.is_empty() {
        col = col.push(text("VoIP extraction lands in Phase 3.").size(13));
    }
    for v in &app.case.voip_calls {
        col = col.push(
            text(format!(
                "{}  {} → {}  ({})",
                v.call_id, v.from, v.to, v.codec
            ))
            .size(12),
        );
    }
    panel("VoIP", col)
}
