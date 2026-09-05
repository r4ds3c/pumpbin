//! Artifact post-processing and file writers.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::case::{Case, ExtractedFile};

/// If enabled and `name`/bytes look executable, neutralize magic and suffix `.defanged`.
pub fn maybe_defang(name: &str, data: &mut [u8], enabled: bool) -> String {
    if !enabled || !looks_like_executable(name, data) {
        return name.to_string();
    }
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        data[0] = b'X';
        data[1] = b'Z';
    } else if data.len() >= 4 && data.starts_with(b"\x7fELF") {
        data[0] = b'X';
    } else if data.len() >= 4
        && (data.starts_with(b"\xfe\xed\xfa") || data.starts_with(b"\xcf\xfa\xed"))
    {
        data[0] = data[0].wrapping_add(1);
    }
    format!("{name}.defanged")
}

fn looks_like_executable(name: &str, data: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".sys")
        || lower.ends_with(".so")
        || lower.ends_with(".dylib")
        || (data.len() >= 2 && data[0] == b'M' && data[1] == b'Z')
        || (data.len() >= 4 && data.starts_with(b"\x7fELF"))
}

pub struct SaveOpts<'a> {
    pub output_dir: &'a Path,
    pub defang: bool,
    pub protocol: &'a str,
    pub source_host: Option<IpAddr>,
    pub dest_host: Option<IpAddr>,
    pub content_type: Option<String>,
}

pub fn save_extracted(
    case: &mut Case,
    name: &str,
    mut data: Vec<u8>,
    opts: SaveOpts<'_>,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let name = maybe_defang(name, &mut data, opts.defang);
    let path = unique_path(opts.output_dir, &name);
    std::fs::write(&path, &data)?;
    let sha256 = hex_sha256(&data);
    let is_image = is_image_name(&name)
        || opts
            .content_type
            .as_deref()
            .map(|c| c.to_ascii_lowercase().starts_with("image/"))
            .unwrap_or(false);
    let file = ExtractedFile {
        name,
        path,
        size: data.len() as u64,
        sha256: sha256.clone(),
        source_host: opts.source_host,
        dest_host: opts.dest_host,
        protocol: opts.protocol.to_string(),
        content_type: opts.content_type,
        is_image,
    };
    if is_image {
        case.images.push(file.clone());
    }
    if !case.files.iter().any(|f| f.sha256 == sha256) {
        case.files.push(file);
    }
    Ok(())
}

pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let mut path = dir.join(name);
    if !path.exists() {
        return path;
    }
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    for i in 1..10_000 {
        path = dir.join(format!("{stem}_{i}.{ext}"));
        if !path.exists() {
            return path;
        }
    }
    dir.join(format!("{stem}_{}.bin", &hex_sha256(name.as_bytes())[..8]))
}

pub fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

pub fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "object.bin".into()
    } else {
        s
    }
}

fn is_image_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with(".png")
        || l.ends_with(".jpg")
        || l.ends_with(".jpeg")
        || l.ends_with(".gif")
        || l.ends_with(".bmp")
        || l.ends_with(".webp")
}
