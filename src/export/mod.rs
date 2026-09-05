//! Case export: CSV, XML, CASE, JSON-LD.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::case::Case;

pub fn export_json(case: &Case, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(case).context("serialize case")?;
    write_all(path, json.as_bytes())
}

pub fn export_hosts_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "ip,country,asn,os,color,hostnames,user_agents,open_ports,bytes_sent,bytes_recv"
    )?;
    for host in case.hosts.values() {
        writeln!(
            f,
            "{},{},{},{},{},\"{}\",\"{}\",\"{}\",{},{}",
            host.ip,
            host.country.as_deref().unwrap_or(""),
            host.asn.as_deref().unwrap_or(""),
            host.os_guess.as_deref().unwrap_or(""),
            host.color.as_deref().unwrap_or(""),
            host.hostnames.join(";"),
            host.user_agents.join(";"),
            host.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(";"),
            host.bytes_sent,
            host.bytes_recv
        )?;
    }
    Ok(())
}

pub fn export_sessions_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "proto,app_proto,pipi,src,sport,dst,dport,packets,bytes_a_to_b,bytes_b_to_a"
    )?;
    for s in &case.sessions {
        writeln!(
            f,
            "{},{},{},{},{},{},{},{},{},{}",
            s.proto,
            s.app_proto.as_deref().unwrap_or(""),
            s.pipi.as_deref().unwrap_or(""),
            s.src,
            s.sport,
            s.dst,
            s.dport,
            s.packets,
            s.bytes_a_to_b,
            s.bytes_b_to_a
        )?;
    }
    Ok(())
}

pub fn export_dns_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "frame,qtype,query,answers,whitelisted,tracker")?;
    for d in &case.dns_records {
        writeln!(
            f,
            "{},{},{},\"{}\",{},{}",
            d.frame,
            d.qtype,
            d.query,
            d.answers.join(";"),
            d.whitelisted,
            d.is_tracker
        )?;
    }
    Ok(())
}

pub fn export_files_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "name,protocol,size,sha256,content_type,path")?;
    for file in &case.files {
        writeln!(
            f,
            "{},{},{},{},{},{}",
            csv_escape(&file.name),
            file.protocol,
            file.size,
            file.sha256,
            file.content_type.as_deref().unwrap_or(""),
            file.path.display()
        )?;
    }
    Ok(())
}

pub fn export_credentials_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "protocol,username,secret,host,details")?;
    for c in &case.credentials {
        writeln!(
            f,
            "{},{},{},{},{}",
            c.protocol,
            csv_escape(&c.username),
            csv_escape(&c.secret),
            c.host.map(|h| h.to_string()).unwrap_or_default(),
            csv_escape(&c.details)
        )?;
    }
    Ok(())
}

pub fn export_parameters_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "name,value,source,host")?;
    for p in &case.parameters {
        writeln!(
            f,
            "{},{},{},{}",
            csv_escape(&p.name),
            csv_escape(&p.value),
            p.source,
            p.host.map(|h| h.to_string()).unwrap_or_default()
        )?;
    }
    Ok(())
}

pub fn export_keywords_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "frame,keyword,session,context")?;
    for k in &case.keywords {
        writeln!(
            f,
            "{},{},{},{}",
            k.frame,
            csv_escape(&k.keyword),
            csv_escape(&k.session),
            csv_escape(&k.context)
        )?;
    }
    Ok(())
}

/// Excel-friendly CSV uses `;` separator and UTF-8 BOM.
pub fn export_hosts_excel_csv(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    f.write_all(&[0xEF, 0xBB, 0xBF])?;
    writeln!(f, "ip;country;asn;os;hostnames;open_ports")?;
    for host in case.hosts.values() {
        writeln!(
            f,
            "{};{};{};{};{};{}",
            host.ip,
            host.country.as_deref().unwrap_or(""),
            host.asn.as_deref().unwrap_or(""),
            host.os_guess.as_deref().unwrap_or(""),
            host.hostnames.join("|"),
            host.open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("|")
        )?;
    }
    Ok(())
}

pub fn export_xml(case: &Case, path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(f, "<HostSightCase>")?;
    if let Some(src) = &case.source_path {
        writeln!(f, "  <Source>{}</Source>", xml_escape(&src.display().to_string()))?;
    }
    writeln!(f, "  <Hosts>")?;
    for h in case.hosts.values() {
        writeln!(
            f,
            r#"    <Host ip="{}" country="{}" asn="{}" os="{}">"#,
            h.ip,
            xml_escape(h.country.as_deref().unwrap_or("")),
            xml_escape(h.asn.as_deref().unwrap_or("")),
            xml_escape(h.os_guess.as_deref().unwrap_or(""))
        )?;
        for name in &h.hostnames {
            writeln!(f, "      <Hostname>{}</Hostname>", xml_escape(name))?;
        }
        writeln!(f, "    </Host>")?;
    }
    writeln!(f, "  </Hosts>")?;
    writeln!(f, "  <Files count=\"{}\">", case.files.len())?;
    for file in &case.files {
        writeln!(
            f,
            r#"    <File name="{}" sha256="{}" size="{}" protocol="{}"/>"#,
            xml_escape(&file.name),
            file.sha256,
            file.size,
            file.protocol
        )?;
    }
    writeln!(f, "  </Files>")?;
    writeln!(f, "  <Dns count=\"{}\">", case.dns_records.len())?;
    for d in &case.dns_records {
        writeln!(
            f,
            r#"    <Query name="{}" type="{}" whitelisted="{}" tracker="{}"/>"#,
            xml_escape(&d.query),
            d.qtype,
            d.whitelisted,
            d.is_tracker
        )?;
    }
    writeln!(f, "  </Dns>")?;
    writeln!(f, "</HostSightCase>")?;
    Ok(())
}

/// Minimal Cyber-investigation Analysis Standard Expression (CASE) JSON graph.
pub fn export_case(case: &Case, path: &Path) -> Result<()> {
    let mut objects = Vec::new();
    objects.push(serde_json::json!({
        "@id": "case-1",
        "@type": "case:InvestigativeAction",
        "name": "HostSight parse",
        "description": case.summary(),
    }));
    for (i, h) in case.hosts.values().enumerate() {
        objects.push(serde_json::json!({
            "@id": format!("host-{i}"),
            "@type": "obs:IPv4Address",
            "value": h.ip.to_string(),
            "hostnames": h.hostnames,
            "country": h.country,
            "asn": h.asn,
        }));
    }
    for (i, file) in case.files.iter().enumerate() {
        objects.push(serde_json::json!({
            "@id": format!("file-{i}"),
            "@type": "obs:File",
            "name": file.name,
            "hash": [{"@type": "Hash", "hashMethod": "SHA256", "hashValue": file.sha256}],
            "sizeInBytes": file.size,
        }));
    }
    let doc = serde_json::json!({
        "@context": {
            "case": "https://ontology.caseontology.org/case/case#",
            "obs": "https://ontology.unifiedcyberontology.org/uco/observable#"
        },
        "@graph": objects,
    });
    write_all(path, serde_json::to_string_pretty(&doc)?.as_bytes())
}

pub fn export_json_ld(case: &Case, path: &Path) -> Result<()> {
    let doc = serde_json::json!({
        "@context": "https://schema.org",
        "@type": "Dataset",
        "name": "HostSight case export",
        "description": case.summary(),
        "variableMeasured": [
            {"@type": "PropertyValue", "name": "hosts", "value": case.hosts.len()},
            {"@type": "PropertyValue", "name": "files", "value": case.files.len()},
            {"@type": "PropertyValue", "name": "dns", "value": case.dns_records.len()},
            {"@type": "PropertyValue", "name": "sessions", "value": case.sessions.len()},
        ],
        "hasPart": case.hosts.values().map(|h| serde_json::json!({
            "@type": "ComputerNetwork",
            "identifier": h.ip.to_string(),
            "name": h.hostnames.first(),
            "addressCountry": h.country,
        })).collect::<Vec<_>>(),
    });
    write_all(path, serde_json::to_string_pretty(&doc)?.as_bytes())
}

/// Export a directory of standard views (counts match GUI).
pub fn export_all(case: &Case, dir: &Path) -> Result<ExportManifest> {
    std::fs::create_dir_all(dir)?;
    export_hosts_csv(case, &dir.join("hosts.csv"))?;
    export_hosts_excel_csv(case, &dir.join("hosts_excel.csv"))?;
    export_sessions_csv(case, &dir.join("sessions.csv"))?;
    export_dns_csv(case, &dir.join("dns.csv"))?;
    export_files_csv(case, &dir.join("files.csv"))?;
    export_credentials_csv(case, &dir.join("credentials.csv"))?;
    export_parameters_csv(case, &dir.join("parameters.csv"))?;
    export_keywords_csv(case, &dir.join("keywords.csv"))?;
    export_json(case, &dir.join("case.json"))?;
    export_xml(case, &dir.join("case.xml"))?;
    export_case(case, &dir.join("case.case.json"))?;
    export_json_ld(case, &dir.join("case.jsonld"))?;
    Ok(ExportManifest {
        hosts: case.hosts.len(),
        sessions: case.sessions.len(),
        dns: case.dns_records.len(),
        files: case.files.len(),
        credentials: case.credentials.len(),
        parameters: case.parameters.len(),
        keywords: case.keywords.len(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportManifest {
    pub hosts: usize,
    pub sessions: usize,
    pub dns: usize,
    pub files: usize,
    pub credentials: usize,
    pub parameters: usize,
    pub keywords: usize,
}

fn write_all(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
