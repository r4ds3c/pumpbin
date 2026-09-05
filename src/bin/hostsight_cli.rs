//! HostSight CLI — batch open captures, extract, export (NetworkMinerCLI analogue).

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use hostsight::capture::{self, IngestOptions};
use hostsight::export;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        bail!("missing command");
    };

    match cmd.as_str() {
        "parse" | "carve" => {
            let capture_path = PathBuf::from(args.next().context("missing capture/dump path")?);
            let mut out_dir = std::env::temp_dir().join("hostsight-out");
            let mut export_json: Option<PathBuf> = None;
            let mut export_hosts: Option<PathBuf> = None;
            let mut opts = IngestOptions::default();
            let force_carve = cmd == "carve";

            while let Some(a) = args.next() {
                match a.as_str() {
                    "--out" => out_dir = PathBuf::from(args.next().context("--out needs path")?),
                    "--export-json" => {
                        export_json = Some(PathBuf::from(
                            args.next().context("--export-json needs path")?,
                        ))
                    }
                    "--export-hosts-csv" => {
                        export_hosts = Some(PathBuf::from(
                            args.next().context("--export-hosts-csv needs path")?,
                        ))
                    }
                    "--keywords" => {
                        opts.keywords = args.next().context("--keywords needs string")?;
                    }
                    "--no-defang" => opts.defang_executables = false,
                    other => bail!("unknown arg: {other}"),
                }
            }

            std::fs::create_dir_all(&out_dir)?;
            let case = if force_carve {
                capture::carver::carve_file(&capture_path, &out_dir, &opts)?
            } else {
                capture::ingest_file(&capture_path, &out_dir, &opts)?
            };
            println!("{}", case.summary());
            if let Some(p) = export_json {
                export::export_json(&case, &p)?;
                println!("wrote {}", p.display());
            }
            if let Some(p) = export_hosts {
                export::export_hosts_csv(&case, &p)?;
                println!("wrote {}", p.display());
            }
            Ok(())
        }
        "pcap-over-ip" => {
            let mode = args.next().context("listen|connect")?;
            let addr = args.next().context("bind/connect address")?;
            let mut out_dir = std::env::temp_dir().join("hostsight-out");
            let mut opts = IngestOptions::default();
            let mut max_packets = Some(10_000u64);
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--out" => out_dir = PathBuf::from(args.next().context("--out")?),
                    "--max" => {
                        max_packets = Some(
                            args.next()
                                .context("--max")?
                                .parse()
                                .context("max packets")?,
                        )
                    }
                    "--no-defang" => opts.defang_executables = false,
                    other => bail!("unknown arg: {other}"),
                }
            }
            std::fs::create_dir_all(&out_dir)?;
            let case = match mode.as_str() {
                "listen" => {
                    capture::pcap_over_ip::ingest_listen(&addr, &out_dir, &opts, max_packets)?
                }
                "connect" => {
                    capture::pcap_over_ip::ingest_connect(&addr, &out_dir, &opts, max_packets)?
                }
                _ => bail!("mode must be listen or connect"),
            };
            println!("{}", case.summary());
            Ok(())
        }
        "devices" => {
            for d in capture::live::list_devices()? {
                println!("{}\t{}", d.name, d.description);
            }
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            bail!("unknown command: {other}");
        }
    }
}

fn print_usage() {
    eprintln!(
        "HostSight CLI\n\nCommands:\n  parse <file> [--out DIR] [--export-json FILE] [--keywords TEXT] [--no-defang]\n  carve <dump>  — force Network Packet Carver\n  pcap-over-ip listen|connect <addr> [--out DIR] [--max N]\n  devices       — list live interfaces (needs --features live-capture)\n"
    );
}
