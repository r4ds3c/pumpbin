//! FTP control-channel credentials, commands, and RETR/STOR name hints.

use std::net::IpAddr;

use crate::case::{Case, Credential, Parameter};

pub fn handle_segment(case: &mut Case, payload: &[u8], src: IpAddr, dst: IpAddr, sport: u16, dport: u16) {
    if !(dport == 21 || sport == 21 || looks_like_ftp(payload)) {
        return;
    }
    let text = String::from_utf8_lossy(payload);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("USER ") {
            let user = line[line.len() - rest.len()..].trim();
            case.credentials.push(Credential {
                protocol: "FTP".into(),
                username: user.to_string(),
                secret: String::new(),
                host: Some(dst),
                details: "USER".into(),
            });
            case.parameters.push(Parameter {
                name: "USER".into(),
                value: user.to_string(),
                source: "FTP".into(),
                host: Some(dst),
            });
        } else if let Some(rest) = upper.strip_prefix("PASS ") {
            let pass = line[line.len() - rest.len()..].trim();
            if let Some(last) = case
                .credentials
                .iter_mut()
                .rev()
                .find(|c| c.protocol == "FTP" && c.secret.is_empty())
            {
                last.secret = pass.to_string();
            } else {
                case.credentials.push(Credential {
                    protocol: "FTP".into(),
                    username: String::new(),
                    secret: pass.to_string(),
                    host: Some(dst),
                    details: "PASS".into(),
                });
            }
        } else if let Some(rest) = upper
            .strip_prefix("RETR ")
            .or_else(|| upper.strip_prefix("STOR "))
            .or_else(|| upper.strip_prefix("SIZE "))
        {
            let cmd = line.split_whitespace().next().unwrap_or("FTP");
            let name = line[line.len() - rest.len()..].trim();
            case.parameters.push(Parameter {
                name: cmd.to_string(),
                value: name.to_string(),
                source: "FTP".into(),
                host: Some(if sport == 21 { src } else { dst }),
            });
        }
    }
}

fn looks_like_ftp(payload: &[u8]) -> bool {
    payload.starts_with(b"USER ")
        || payload.starts_with(b"PASS ")
        || payload.starts_with(b"RETR ")
        || payload.starts_with(b"STOR ")
        || payload.starts_with(b"220 ")
        || payload.starts_with(b"331 ")
}
