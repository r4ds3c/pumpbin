fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("logo/icon.ico");
        res.compile().unwrap();
    }

    #[cfg(target_os = "macos")]
    {
        use std::fs;

        let version = env!("CARGO_PKG_VERSION");
        fs::write("VERSION", version).unwrap();
    }

    // Live capture on Windows needs Npcap SDK's wpcap.lib on the linker path.
    if std::env::var_os("CARGO_FEATURE_LIVE_CAPTURE").is_some() {
        #[cfg(target_os = "windows")]
        windows_live_capture_link();
    }
}

#[cfg(target_os = "windows")]
fn windows_live_capture_link() {
    use std::path::PathBuf;

    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=NPCAP_SDK");

    if let Ok(dir) = std::env::var("LIBPCAP_LIBDIR") {
        let p = PathBuf::from(&dir);
        if p.join("wpcap.lib").is_file() {
            println!("cargo:rustc-link-search=native={}", p.display());
            return;
        }
        panic!(
            "LIBPCAP_LIBDIR is set to {dir} but wpcap.lib was not found there.\n\
             Point it at the Npcap SDK Lib\\x64 folder."
        );
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(sdk) = std::env::var("NPCAP_SDK") {
        let sdk = PathBuf::from(sdk);
        candidates.push(sdk.join("Lib").join("x64"));
        candidates.push(sdk.join("Lib"));
    }
    candidates.extend([
        PathBuf::from(r"C:\npcap-sdk\Lib\x64"),
        PathBuf::from(r"C:\npcap-sdk\Lib"),
        PathBuf::from(r"C:\Program Files\Npcap\SDK\Lib\x64"),
        PathBuf::from(r"C:\Program Files\Npcap\SDK\Lib"),
        PathBuf::from(r"C:\Program Files (x86)\Npcap\SDK\Lib\x64"),
    ]);

    // Local/vendor or cached SDK under the crate or LOCALAPPDATA
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        candidates.push(PathBuf::from(&manifest).join("deps").join("npcap-sdk").join("Lib").join("x64"));
        candidates.push(PathBuf::from(&manifest).join("third_party").join("npcap-sdk").join("Lib").join("x64"));
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local)
                .join("hostsight")
                .join("npcap-sdk")
                .join("Lib")
                .join("x64"),
        );
    }

    for dir in &candidates {
        if dir.join("wpcap.lib").is_file() {
            println!("cargo:rustc-link-search=native={}", dir.display());
            println!("cargo:warning=Using Npcap SDK libs from {}", dir.display());
            return;
        }
    }

    // Try to fetch the official SDK into %LOCALAPPDATA%\hostsight\npcap-sdk
    if let Some(libdir) = try_fetch_npcap_sdk() {
        if libdir.join("wpcap.lib").is_file() {
            println!("cargo:rustc-link-search=native={}", libdir.display());
            println!(
                "cargo:warning=Downloaded Npcap SDK libs to {}",
                libdir.display()
            );
            return;
        }
    }

    panic!(
        "\n\n\
         live-capture on Windows needs Npcap SDK (wpcap.lib) for linking.\n\n\
         Quick fix:\n\
           1. Install Npcap runtime: https://npcap.com/#download\n\
              (enable \"WinPcap API-compatible Mode\")\n\
           2. Download SDK: https://npcap.com/dist/npcap-sdk-1.16.zip\n\
           3. Extract, then set:\n\
                $env:LIBPCAP_LIBDIR = \"C:\\path\\to\\npcap-sdk\\Lib\\x64\"\n\
           4. cargo run --bin hostsight --features live-capture\n\n\
         Or place the SDK at C:\\npcap-sdk or %LOCALAPPDATA%\\hostsight\\npcap-sdk\n\
         so HostSight can find Lib\\x64\\wpcap.lib automatically.\n"
    );
}

#[cfg(target_os = "windows")]
fn try_fetch_npcap_sdk() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    use std::process::Command;

    let local = std::env::var_os("LOCALAPPDATA")?;
    let root = PathBuf::from(local).join("hostsight").join("npcap-sdk");
    let libdir = root.join("Lib").join("x64");
    if libdir.join("wpcap.lib").is_file() {
        return Some(libdir);
    }

    let _ = std::fs::create_dir_all(&root);
    let zip_path = root.join("npcap-sdk-1.16.zip");
    let url = "https://npcap.com/dist/npcap-sdk-1.16.zip";

    println!("cargo:warning=Npcap SDK not found; downloading {url} …");

    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Invoke-WebRequest -Uri '{url}' -OutFile '{}' -UseBasicParsing",
                zip_path.display()
            ),
        ])
        .status()
        .ok()?;
    if !status.success() || !zip_path.is_file() {
        println!("cargo:warning=Failed to download Npcap SDK (network/admin?). Install manually.");
        return None;
    }

    let expand = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                zip_path.display(),
                root.display()
            ),
        ])
        .status()
        .ok()?;
    if !expand.success() {
        println!("cargo:warning=Failed to extract Npcap SDK zip.");
        return None;
    }

    // Zip may extract into npcap-sdk-1.16/ or flat Lib/
    let candidates = [
        root.join("Lib").join("x64"),
        root.join("npcap-sdk-1.16").join("Lib").join("x64"),
    ];
    for c in candidates {
        if c.join("wpcap.lib").is_file() {
            // Normalize to root/Lib/x64 for next builds
            if c != libdir {
                let _ = std::fs::create_dir_all(&libdir);
                let _ = std::fs::copy(c.join("wpcap.lib"), libdir.join("wpcap.lib"));
                let packet = c.join("Packet.lib");
                if packet.is_file() {
                    let _ = std::fs::copy(&packet, libdir.join("Packet.lib"));
                }
            }
            if libdir.join("wpcap.lib").is_file() {
                return Some(libdir);
            }
            return Some(c);
        }
    }
    // Search recursively for wpcap.lib
    find_wpcap_lib(&root)
}

#[cfg(target_os = "windows")]
fn find_wpcap_lib(root: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::fs;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = fs::read_dir(&dir).ok()?;
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().and_then(|n| n.to_str()) == Some("wpcap.lib") {
                return p.parent().map(|p| p.to_path_buf());
            }
        }
    }
    None
}
