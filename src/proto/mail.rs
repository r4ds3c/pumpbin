//! SMTP / POP3 / IMAP cleartext credentials and message extraction.

use std::net::IpAddr;

use crate::case::{Case, Credential, MessageArtifact, Parameter};

pub fn handle_segment(case: &mut Case, payload: &[u8], src: IpAddr, dst: IpAddr, sport: u16, dport: u16) {
    let port = if is_mail_port(sport) {
        sport
    } else if is_mail_port(dport) {
        dport
    } else if looks_mail(payload) {
        dport
    } else {
        return;
    };

    let proto = match port {
        25 | 587 | 465 => "SMTP",
        110 | 995 => "POP3",
        143 | 993 => "IMAP",
        _ => {
            if payload.starts_with(b"MAIL FROM:") || payload.starts_with(b"RCPT TO:") {
                "SMTP"
            } else if payload.starts_with(b"USER ") || payload.starts_with(b"+OK") {
                "POP3"
            } else if payload.starts_with(b"a LOGIN") || payload.starts_with(b"* OK") {
                "IMAP"
            } else {
                return;
            }
        }
    };

    let text = String::from_utf8_lossy(payload);
    match proto {
        "SMTP" => handle_smtp(case, &text, dst),
        "POP3" => handle_pop3(case, &text, dst),
        "IMAP" => handle_imap(case, &text, dst),
        _ => {}
    }

    // Capture AUTH PLAIN blobs as parameters
    for line in text.lines() {
        let u = line.trim();
        if u.to_ascii_uppercase().starts_with("AUTH ") {
            case.parameters.push(Parameter {
                name: "AUTH".into(),
                value: u.to_string(),
                source: proto.into(),
                host: Some(dst),
            });
        }
    }
    let _ = src;
}

fn is_mail_port(p: u16) -> bool {
    matches!(p, 25 | 587 | 465 | 110 | 995 | 143 | 993)
}

fn looks_mail(p: &[u8]) -> bool {
    p.starts_with(b"MAIL FROM:")
        || p.starts_with(b"RCPT TO:")
        || p.starts_with(b"DATA")
        || p.starts_with(b"USER ")
        || p.starts_with(b"PASS ")
        || p.starts_with(b"AUTH ")
        || p.windows(6).any(|w| w.eq_ignore_ascii_case(b"LOGIN "))
}

fn handle_smtp(case: &mut Case, text: &str, host: IpAddr) {
    let mut from = String::new();
    let mut to = Vec::new();

    for line in text.lines() {
        let t = line.trim_end();
        let upper = t.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("MAIL FROM:") {
            from = t[t.len() - rest.len()..]
                .trim()
                .trim_matches(|c| c == '<' || c == '>')
                .to_string();
        } else if let Some(rest) = upper.strip_prefix("RCPT TO:") {
            to.push(
                t[t.len() - rest.len()..]
                    .trim()
                    .trim_matches(|c| c == '<' || c == '>')
                    .to_string(),
            );
        }
    }

    if let Some(data_idx) = text.to_ascii_uppercase().find("\nDATA\r\n")
        .or_else(|| text.to_ascii_uppercase().find("\nDATA\n"))
        .or_else(|| {
            if text.to_ascii_uppercase().starts_with("DATA\r\n")
                || text.to_ascii_uppercase().starts_with("DATA\n")
            {
                Some(0)
            } else {
                None
            }
        })
    {
        let after = if text[data_idx..].to_ascii_uppercase().starts_with("DATA") {
            // find end of DATA line
            text[data_idx..]
                .find('\n')
                .map(|i| &text[data_idx + i + 1..])
                .unwrap_or("")
        } else {
            let rest = &text[data_idx + 1..]; // skip leading \n
            rest.find('\n').map(|i| &rest[i + 1..]).unwrap_or("")
        };
        let body_part = after.split("\r\n.\r\n").next().unwrap_or(after);
        let body_part = body_part.split("\n.\n").next().unwrap_or(body_part);
        let mut subject = String::new();
        let mut preview = String::new();
        let mut in_body = false;
        for line in body_part.lines() {
            if !in_body {
                if line.is_empty() {
                    in_body = true;
                } else if line.to_ascii_lowercase().starts_with("subject:") {
                    subject = line[8..].trim().to_string();
                }
            } else {
                preview.push_str(line);
                preview.push('\n');
                if preview.len() > 400 {
                    break;
                }
            }
        }
        if !from.is_empty() || !subject.is_empty() || !preview.is_empty() {
            case.messages.push(MessageArtifact {
                protocol: "SMTP".into(),
                subject,
                from,
                to: to.join(", "),
                body_preview: preview.chars().take(400).collect(),
            });
        }
    }

    for line in text.lines() {
        let u = line.trim();
        if let Some(b64) = u
            .strip_prefix("AUTH PLAIN ")
            .or_else(|| u.strip_prefix("AUTH PLAIN\t"))
        {
            if let Ok(raw) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
            {
                let parts: Vec<_> = raw.split(|&b| b == 0).collect();
                if parts.len() >= 3 {
                    case.credentials.push(Credential {
                        protocol: "SMTP AUTH PLAIN".into(),
                        username: String::from_utf8_lossy(parts[1]).into_owned(),
                        secret: String::from_utf8_lossy(parts[2]).into_owned(),
                        host: Some(host),
                        details: String::new(),
                    });
                }
            }
        }
    }
}

fn handle_pop3(case: &mut Case, text: &str, host: IpAddr) {
    let mut user = String::new();
    for line in text.lines() {
        let t = line.trim();
        let upper = t.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("USER ") {
            user = t[t.len() - rest.len()..].trim().to_string();
            case.credentials.push(Credential {
                protocol: "POP3".into(),
                username: user.clone(),
                secret: String::new(),
                host: Some(host),
                details: "USER".into(),
            });
        } else if let Some(rest) = upper.strip_prefix("PASS ") {
            let pass = t[t.len() - rest.len()..].trim().to_string();
            if let Some(c) = case
                .credentials
                .iter_mut()
                .rev()
                .find(|c| c.protocol == "POP3" && c.secret.is_empty())
            {
                c.secret = pass;
            } else {
                case.credentials.push(Credential {
                    protocol: "POP3".into(),
                    username: user.clone(),
                    secret: pass,
                    host: Some(host),
                    details: "PASS".into(),
                });
            }
        }
    }
}

fn handle_imap(case: &mut Case, text: &str, host: IpAddr) {
    for line in text.lines() {
        let t = line.trim();
        // tag LOGIN "user" "pass"
        let upper = t.to_ascii_uppercase();
        if let Some(idx) = upper.find(" LOGIN ") {
            let rest = &t[idx + 7..];
            let parts = split_imap_args(rest);
            if parts.len() >= 2 {
                case.credentials.push(Credential {
                    protocol: "IMAP LOGIN".into(),
                    username: parts[0].clone(),
                    secret: parts[1].clone(),
                    host: Some(host),
                    details: String::new(),
                });
            }
        }
    }
}

fn split_imap_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => in_q = !in_q,
            ' ' if !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
