//! iced UI: NetworkMiner-style host-centric Pro layout.

use iced::{
    alignment::Vertical,
    widget::{
        button, column, container, horizontal_rule, row, scrollable, text, text_input,
        vertical_rule, Column, Row, Space,
    },
    Element, Length, Padding,
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
    Browser,
}

impl Tab {
    pub const ALL: [Tab; 12] = [
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
        Tab::Browser,
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
            Tab::Browser => "Browser",
        }
    }
}

pub fn view(app: &HostSight) -> Element<'_, Message> {
    let toolbar = toolbar_row(app);
    let live = live_row(app);
    let filter_row = row![
        text("CIDR").size(12),
        text_input("e.g. 10.0.0.0/8 — Reload to apply", &app.cidr_filter)
            .on_input(Message::CidrFilterChanged)
            .width(Length::Fill),
        text(format!("out: {}", truncate_path(&app.output_dir.display().to_string(), 42))).size(11),
    ]
    .spacing(8)
    .align_y(Vertical::Center)
    .padding([4, 8]);

    let tabs = Tab::ALL.iter().fold(Row::new().spacing(3), |row, tab| {
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
        Tab::Browser => browser_view(app),
    };

    let status = status_bar(app);

    column![
        toolbar,
        live,
        horizontal_rule(1),
        filter_row,
        tabs.padding([0, 8]),
        body,
        horizontal_rule(1),
        status,
    ]
    .spacing(0)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn toolbar_row(app: &HostSight) -> Element<'_, Message> {
    row![
        button(text("Open").size(12)).on_press(Message::OpenCaptureClicked),
        button(text("Carve").size(12)).on_press(Message::OpenCarveClicked),
        button(text("Reload").size(12)).on_press(Message::ReloadCase),
        button(text("Clear").size(12)).on_press(Message::ClearCase),
        Space::with_width(10),
        button(text("Output").size(12)).on_press(Message::OutputDirClicked),
        button(text("Open out").size(12)).on_press(Message::OpenOutputFolder),
        button(text(if app.defang_executables {
            "Defang ON"
        } else {
            "Defang OFF"
        }).size(12))
        .on_press(Message::ToggleDefang),
        button(text(app.timezone.label()).size(12)).on_press(Message::CycleTimezone),
        button(text("Export all").size(12)).on_press(Message::ExportAllClicked),
        Space::with_width(Length::Fill),
        text(if app.busy {
            "Working…"
        } else if app.live_running {
            "CAPTURING"
        } else {
            "Ready"
        })
        .size(12),
    ]
    .spacing(6)
    .align_y(Vertical::Center)
    .padding(Padding::from([8, 8]))
    .into()
}

fn live_row(app: &HostSight) -> Element<'_, Message> {
    let device_label = match app.live_device_idx.and_then(|i| app.live_devices.get(i)) {
        Some(d) => truncate_path(&d.label(), 56),
        None if app.live_devices.is_empty() => "No interface — Refresh".into(),
        None => "Select interface".into(),
    };

    let mut device_btns = Row::new().spacing(4);
    for (i, _) in app.live_devices.iter().enumerate().take(6) {
        let selected = app.live_device_idx == Some(i);
        let label = text(format!("#{i}")).size(11);
        let btn = if selected {
            button(label).style(style::button::selected)
        } else {
            button(label).style(style::button::unselected)
        }
        .on_press(Message::LiveSelectDevice(i));
        device_btns = device_btns.push(btn);
    }
    if app.live_devices.len() > 6 {
        device_btns = device_btns.push(text(format!("+{}", app.live_devices.len() - 6)).size(11));
    }

    let start_stop = if app.live_running {
        button(text("Stop").size(12)).on_press(Message::LiveStop)
    } else {
        button(text("Start live").size(12)).on_press(Message::LiveStart)
    };

    let next_iface = if app.live_devices.len() > 1 {
        let next = app
            .live_device_idx
            .map(|i| (i + 1) % app.live_devices.len())
            .unwrap_or(0);
        button(text("Next iface").size(12)).on_press(Message::LiveSelectDevice(next))
    } else {
        button(text("Next iface").size(12))
    };

    row![
        text("Live").size(12),
        button(text("Refresh ifaces").size(12)).on_press(Message::LiveRefreshDevices),
        device_btns,
        next_iface,
        text(device_label).size(11).width(Length::Fill),
        start_stop,
        text(format!("pkts {}", app.live_packets)).size(12),
        text(format!("batches {}", app.live_batches)).size(11),
    ]
    .spacing(8)
    .align_y(Vertical::Center)
    .padding([4, 8])
    .into()
}

fn status_bar(app: &HostSight) -> Element<'_, Message> {
    let src = app
        .last_capture_path
        .as_ref()
        .map(|p| truncate_path(&p.display().to_string(), 48))
        .unwrap_or_else(|| {
            if app.live_packets > 0 {
                "live sniff".into()
            } else {
                "(no source)".into()
            }
        });
    let counts = format!(
        "Hosts {} · Sess {} · DNS {} · Files {} · Creds {} · Msgs {} · VoIP {} · Img {}",
        app.case.hosts.len(),
        app.case.sessions.len(),
        app.case.dns_records.len(),
        app.case.files.len(),
        app.case.credentials.len(),
        app.case.messages.len(),
        app.case.voip_calls.len(),
        app.case.images.len(),
    );
    container(
        row![
            text(counts).size(11).width(Length::Fill),
            text(format!("src: {src}")).size(11),
            Space::with_width(12),
            text(&app.status).size(11),
        ]
        .spacing(8)
        .align_y(Vertical::Center),
    )
    .padding([6, 8])
    .width(Length::Fill)
    .into()
}

fn panel<'a>(title: &'a str, header: Row<'a, Message>, rows: Column<'a, Message>) -> Element<'a, Message> {
    container(
        column![
            text(title).size(15),
            header,
            horizontal_rule(1),
            scrollable(rows.spacing(1).padding([2, 0])).height(Length::Fill),
        ]
        .spacing(6)
        .padding(8),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn col_header<'a>(labels: &'a [&'a str], widths: &'a [Length]) -> Row<'a, Message> {
    let mut r = Row::new().spacing(6).padding([0, 4]);
    for (i, label) in labels.iter().enumerate() {
        let w = widths.get(i).copied().unwrap_or(Length::Fill);
        r = r.push(text(*label).size(11).width(w));
    }
    r
}

fn hosts_view(app: &HostSight) -> Element<'_, Message> {
    let mut list = Column::new().spacing(2);
    if app.case.hosts.is_empty() {
        list = list.push(text("No hosts yet. Open a capture or Start live.").size(12));
    }
    for host in app.case.hosts.values() {
        let selected = app.selected_host == Some(host.ip);
        let color = host.color.as_deref().unwrap_or("·");
        let line = format!(
            "[{}] {}  {}/{}",
            color,
            host.ip,
            host.country.as_deref().unwrap_or("?"),
            host.asn.as_deref().unwrap_or("-"),
        );
        let label = text(line).size(12);
        let btn = if selected {
            button(label).style(style::button::selected).width(Length::Fill)
        } else {
            button(label).style(style::button::unselected).width(Length::Fill)
        }
        .on_press(Message::SelectHost(host.ip));
        list = list.push(btn);
    }

    let detail = host_detail_pane(app);

    row![
        container(
            column![
                text("Host inventory").size(15),
                text(format!("{} hosts", app.case.hosts.len())).size(11),
                horizontal_rule(1),
                scrollable(list).height(Length::Fill),
            ]
            .spacing(6)
            .padding(8),
        )
        .width(Length::Fixed(340.0))
        .height(Length::Fill),
        vertical_rule(1),
        container(detail).width(Length::Fill).height(Length::Fill),
    ]
    .height(Length::Fill)
    .into()
}

fn host_detail_pane(app: &HostSight) -> Element<'_, Message> {
    let Some(ip) = app.selected_host else {
        return column![
            text("Host details").size(15),
            text("Select a host from the inventory.").size(12),
        ]
        .spacing(8)
        .padding(12)
        .into();
    };
    let Some(host) = app.case.hosts.get(&ip) else {
        return column![text("Host not in case.").size(12)].padding(12).into();
    };

    let tls: Vec<_> = app
        .case
        .tls_handshakes
        .iter()
        .filter(|t| t.client == host.ip || t.server == host.ip)
        .take(8)
        .collect();
    let sessions: Vec<_> = app
        .case
        .sessions
        .iter()
        .filter(|s| s.src == host.ip || s.dst == host.ip)
        .take(12)
        .collect();
    let files: Vec<_> = app
        .case
        .files
        .iter()
        .filter(|f| f.source_host == Some(host.ip) || f.dest_host == Some(host.ip))
        .take(8)
        .collect();

    let geo = format!(
        "{}/{}",
        host.country.as_deref().unwrap_or("?"),
        host.asn.as_deref().unwrap_or("?")
    );
    let ports = format!("{:?}", host.open_ports);
    let hostnames = host.hostnames.join(", ");
    let uas = host.user_agents.join(" | ");
    let bytes = format!("↑{}  ↓{}", host.bytes_sent, host.bytes_recv);
    let color = host.color.clone().unwrap_or_else(|| "(none)".into());
    let mac = host.mac.clone().unwrap_or_else(|| "-".into());
    let oui = host.oui_vendor.clone().unwrap_or_else(|| "-".into());
    let os = host.os_guess.clone().unwrap_or_else(|| "-".into());
    let ip_s = host.ip.to_string();

    let mut body = Column::new().spacing(4).padding(12);
    body = body.push(text(format!("Host  {ip_s}")).size(16));
    body = body.push(kv_row("Color", color));
    body = body.push(kv_row("MAC", mac));
    body = body.push(kv_row("OUI", oui));
    body = body.push(kv_row("OS", os));
    body = body.push(kv_row("Geo/ASN", geo));
    body = body.push(kv_row("Ports", ports));
    body = body.push(kv_row("Hostnames", hostnames));
    body = body.push(kv_row("User-Agents", uas));
    body = body.push(kv_row("Bytes", bytes));
    body = body.push(button(text("Cycle color").size(12)).on_press(Message::CycleHostColor(ip)));

    body = body.push(text("TLS").size(13));
    if tls.is_empty() {
        body = body.push(text("(none)").size(11));
    }
    for t in tls {
        body = body.push(
            text(format!(
                "SNI:{:?} JA3:{:?} JA4:{:?}",
                t.sni, t.ja3, t.ja4
            ))
            .size(11),
        );
    }

    body = body.push(text("Sessions").size(13));
    for s in sessions {
        body = body.push(
            text(format!(
                "{} {}:{} ↔ {}:{}  {}",
                s.proto,
                s.src,
                s.sport,
                s.dst,
                s.dport,
                s.app_proto.as_deref().unwrap_or("-")
            ))
            .size(11),
        );
    }

    body = body.push(text("Files").size(13));
    for f in files {
        body = body.push(text(format!("{}  {} B  {}", f.name, f.size, f.protocol)).size(11));
    }

    scrollable(body).height(Length::Fill).into()
}

fn kv_row(k: &'static str, v: String) -> Element<'static, Message> {
    row![
        text(k).size(11).width(Length::Fixed(100.0)),
        text(v).size(12).width(Length::Fill),
    ]
    .spacing(8)
    .into()
}

fn files_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Name", "Size", "Proto", "SHA256", ""],
        &[
            Length::FillPortion(3),
            Length::Fixed(80.0),
            Length::Fixed(70.0),
            Length::FillPortion(2),
            Length::Fixed(64.0),
        ],
    );
    let mut col = Column::new();
    if app.case.files.is_empty() {
        col = col.push(text("No extracted files.").size(12));
    }
    for (i, f) in app.case.files.iter().enumerate() {
        col = col.push(
            row![
                text(&f.name).size(12).width(Length::FillPortion(3)),
                text(format!("{} B", f.size)).size(12).width(Length::Fixed(80.0)),
                text(&f.protocol).size(12).width(Length::Fixed(70.0)),
                text(format!("{}…", &f.sha256[..16.min(f.sha256.len())]))
                    .size(11)
                    .width(Length::FillPortion(2)),
                button(text("OSINT").size(11)).on_press(Message::OsintFile(i)),
            ]
            .spacing(6)
            .align_y(Vertical::Center),
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
    panel("Files", header, col)
}

fn images_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Name", "Path"],
        &[Length::FillPortion(1), Length::FillPortion(2)],
    );
    let mut col = Column::new();
    if app.case.images.is_empty() {
        col = col.push(text("No images extracted.").size(12));
    }
    for f in &app.case.images {
        col = col.push(
            row![
                text(&f.name).size(12).width(Length::FillPortion(1)),
                text(f.path.display().to_string()).size(11).width(Length::FillPortion(2)),
            ]
            .spacing(6),
        );
    }
    panel("Images", header, col)
}

fn messages_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Proto", "From", "To", "Subject"],
        &[
            Length::Fixed(70.0),
            Length::FillPortion(1),
            Length::FillPortion(1),
            Length::FillPortion(2),
        ],
    );
    let mut col = Column::new();
    if app.case.messages.is_empty() {
        col = col.push(text("No messages yet.").size(12));
    }
    for m in &app.case.messages {
        col = col.push(
            row![
                text(&m.protocol).size(12).width(Length::Fixed(70.0)),
                text(&m.from).size(12).width(Length::FillPortion(1)),
                text(&m.to).size(12).width(Length::FillPortion(1)),
                text(&m.subject).size(12).width(Length::FillPortion(2)),
            ]
            .spacing(6),
        );
    }
    panel("Messages", header, col)
}

fn credentials_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Proto", "User", "Secret", "Details"],
        &[
            Length::Fixed(70.0),
            Length::FillPortion(1),
            Length::FillPortion(1),
            Length::FillPortion(2),
        ],
    );
    let mut col = Column::new();
    if app.case.credentials.is_empty() {
        col = col.push(text("No credentials found.").size(12));
    }
    for c in &app.case.credentials {
        col = col.push(
            row![
                text(&c.protocol).size(12).width(Length::Fixed(70.0)),
                text(&c.username).size(12).width(Length::FillPortion(1)),
                text(&c.secret).size(12).width(Length::FillPortion(1)),
                text(&c.details).size(11).width(Length::FillPortion(2)),
            ]
            .spacing(6),
        );
    }
    panel("Credentials", header, col)
}

fn parameters_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Name", "Value", "Source"],
        &[
            Length::FillPortion(1),
            Length::FillPortion(2),
            Length::Fixed(100.0),
        ],
    );
    let mut col = Column::new();
    if app.case.parameters.is_empty() {
        col = col.push(text("No parameters.").size(12));
    }
    for p in &app.case.parameters {
        col = col.push(
            row![
                text(&p.name).size(12).width(Length::FillPortion(1)),
                text(&p.value).size(12).width(Length::FillPortion(2)),
                text(&p.source).size(11).width(Length::Fixed(100.0)),
            ]
            .spacing(6),
        );
    }
    panel("Parameters", header, col)
}

fn dns_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["#", "Type", "Query", "Answers", "Flags", ""],
        &[
            Length::Fixed(48.0),
            Length::Fixed(48.0),
            Length::FillPortion(2),
            Length::FillPortion(2),
            Length::Fixed(48.0),
            Length::Fixed(64.0),
        ],
    );
    let mut col = Column::new();
    if app.case.dns_records.is_empty() {
        col = col.push(text("No DNS records.").size(12));
    }
    for (i, d) in app.case.dns_records.iter().enumerate() {
        let flags = format!(
            "{}{}",
            if d.whitelisted { "WL" } else { "" },
            if d.is_tracker { "AD" } else { "" }
        );
        col = col.push(
            row![
                text(format!("{}", d.frame)).size(12).width(Length::Fixed(48.0)),
                text(&d.qtype).size(12).width(Length::Fixed(48.0)),
                text(&d.query).size(12).width(Length::FillPortion(2)),
                text(d.answers.join(", ")).size(11).width(Length::FillPortion(2)),
                text(flags).size(11).width(Length::Fixed(48.0)),
                button(text("OSINT").size(11)).on_press(Message::OsintDns(i)),
            ]
            .spacing(6)
            .align_y(Vertical::Center),
        );
    }
    panel("DNS", header, col)
}

fn sessions_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Proto", "App", "Endpoints", "Pkts", "Bytes"],
        &[
            Length::Fixed(48.0),
            Length::Fixed(80.0),
            Length::FillPortion(3),
            Length::Fixed(56.0),
            Length::Fixed(120.0),
        ],
    );
    let mut col = Column::new();
    if app.case.sessions.is_empty() {
        col = col.push(text("No sessions.").size(12));
    }
    for s in &app.case.sessions {
        col = col.push(
            row![
                text(&s.proto).size(12).width(Length::Fixed(48.0)),
                text(format!(
                    "{}/{}",
                    s.app_proto.as_deref().unwrap_or("-"),
                    s.pipi.as_deref().unwrap_or("-")
                ))
                .size(11)
                .width(Length::Fixed(80.0)),
                text(format!("{}:{} ↔ {}:{}", s.src, s.sport, s.dst, s.dport))
                    .size(12)
                    .width(Length::FillPortion(3)),
                text(format!("{}", s.packets)).size(12).width(Length::Fixed(56.0)),
                text(format!("{}/{}", s.bytes_a_to_b, s.bytes_b_to_a))
                    .size(11)
                    .width(Length::Fixed(120.0)),
            ]
            .spacing(6),
        );
    }
    panel("Sessions", header, col)
}

fn keywords_view(app: &HostSight) -> Element<'_, Message> {
    let input = text_input(
        "Keywords (one per line; 0x… for hex). Reload case to re-scan.",
        &app.keyword_draft,
    )
    .on_input(Message::KeywordChanged);

    let header = col_header(
        &["Frame", "Session", "Keyword", "Context"],
        &[
            Length::Fixed(56.0),
            Length::FillPortion(1),
            Length::FillPortion(1),
            Length::FillPortion(2),
        ],
    );
    let mut hits = Column::new();
    if app.case.keywords.is_empty() {
        hits = hits.push(text("No keyword hits. Set keywords and Reload.").size(12));
    }
    for h in &app.case.keywords {
        hits = hits.push(
            row![
                text(format!("{}", h.frame)).size(12).width(Length::Fixed(56.0)),
                text(&h.session).size(11).width(Length::FillPortion(1)),
                text(&h.keyword).size(12).width(Length::FillPortion(1)),
                text(&h.context).size(11).width(Length::FillPortion(2)),
            ]
            .spacing(6),
        );
    }

    container(
        column![
            text("Keywords").size(15),
            input,
            header,
            horizontal_rule(1),
            scrollable(hits).height(Length::Fill),
        ]
        .spacing(8)
        .padding(8),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn anomalies_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(&["Kind", "Detail"], &[Length::Fixed(100.0), Length::Fill]);
    let mut col = Column::new();
    if app.case.anomalies.is_empty() {
        col = col.push(text("No anomalies recorded.").size(12));
    }
    for a in &app.case.anomalies {
        col = col.push(
            row![
                text(&a.kind).size(12).width(Length::Fixed(100.0)),
                text(&a.detail).size(12).width(Length::Fill),
            ]
            .spacing(6),
        );
    }
    panel("Anomalies", header, col)
}

fn browser_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["#", "Method", "URL", "Referer", "UA"],
        &[
            Length::Fixed(36.0),
            Length::Fixed(56.0),
            Length::FillPortion(2),
            Length::FillPortion(1),
            Length::FillPortion(1),
        ],
    );
    let mut col = Column::new();
    if app.case.browser_traces.is_empty() {
        col = col.push(text("No browser hops reconstructed from HTTP.").size(12));
    }
    for (i, h) in app.case.browser_traces.iter().enumerate() {
        col = col.push(
            row![
                text(format!("{}", i + 1)).size(12).width(Length::Fixed(36.0)),
                text(&h.method).size(12).width(Length::Fixed(56.0)),
                text(format!("http://{}{}", h.host, h.path))
                    .size(11)
                    .width(Length::FillPortion(2)),
                text(h.referer.as_deref().unwrap_or("-"))
                    .size(11)
                    .width(Length::FillPortion(1)),
                text(h.user_agent.as_deref().unwrap_or("-"))
                    .size(11)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(6),
        );
    }
    panel("Browser tracing", header, col)
}

fn voip_view(app: &HostSight) -> Element<'_, Message> {
    let header = col_header(
        &["Call-ID", "From", "To", "Codec", "Audio", ""],
        &[
            Length::FillPortion(2),
            Length::FillPortion(1),
            Length::FillPortion(1),
            Length::Fixed(64.0),
            Length::FillPortion(2),
            Length::Fixed(56.0),
        ],
    );
    let mut col = Column::new();
    if app.case.voip_calls.is_empty() {
        col = col.push(text("No VoIP calls. SIP/RTP G.711 extracts appear here.").size(12));
    }
    for (i, v) in app.case.voip_calls.iter().enumerate() {
        let audio = v
            .audio_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(no audio)".into());
        col = col.push(
            row![
                text(&v.call_id).size(11).width(Length::FillPortion(2)),
                text(&v.from).size(12).width(Length::FillPortion(1)),
                text(&v.to).size(12).width(Length::FillPortion(1)),
                text(&v.codec).size(12).width(Length::Fixed(64.0)),
                text(audio).size(11).width(Length::FillPortion(2)),
                button(text("Play").size(11)).on_press(Message::PlayVoip(i)),
            ]
            .spacing(6)
            .align_y(Vertical::Center),
        );
    }
    panel("VoIP", header, col)
}

fn truncate_path(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len().saturating_sub(max - 1)..])
    }
}