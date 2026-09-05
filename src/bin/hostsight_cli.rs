//! HostSight CLI — batch open captures, extract, export (NetworkMinerCLI analogue).

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use hostsight::capture::{self, IngestOptions};
use hostsight::export;
use hostsight::fingerprint::DecodeAsMap;

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
            let mut export_dir: Option<PathBuf> = None;
            let mut export_json: Option<PathBuf> = None;
            let mut export_hosts: Option<PathBuf> = None;
            let mut opts = IngestOptions::default();
            let force_carve = cmd == "carve";

            while let Some(a) = args.next() {
                match a.as_str() {
                    "--out" => out_dir = PathBuf::from(args.next().context("--out needs path")?),
                    "--export-dir" => {
                        export_dir = Some(PathBuf::from(
                            args.next().context("--export-dir needs path")?,
                        ))
                    }
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
                    "--cidr" => {
                        opts.cidr_filter = args.next().context("--cidr needs CIDR list")?;
                    }
                    "--decode-as" => {
                        // format: tcp/443=HTTPS
                        let spec = args.next().context("--decode-as SPEC")?;
                        apply_decode_as(&mut opts.decode_as, &spec)?;
                    }
                    "--geo-db" => {
                        opts.enrich.geo_db_path =
                            Some(PathBuf::from(args.next().context("--geo-db")?));
                    }
                    "--asn-db" => {
                        opts.enrich.asn_db_path =
                            Some(PathBuf::from(args.next().context("--asn-db")?));
                    }
                    "--dns-whitelist" => {
                        opts.enrich.dns_whitelist_path =
                            Some(PathBuf::from(args.next().context("--dns-whitelist")?));
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
            if let Some(dir) = export_dir {
                let m = export::export_all(&case, &dir)?;
                println!(
                    "exported all views to {} (hosts={} sessions={} dns={} files={})",
                    dir.display(),
                    m.hosts,
                    m.sessions,
                    m.dns,
                    m.files
                );
            }
            Ok(())
        }
        "pcap-over-ip" | "packetcache" => {
            let mode = args.next().context("listen|connect")?;
            let addr = args.next().context("bind/connect address")?;
            let mut out_dir = std::env::temp_dir().join("hostsight-out");
            let mut opts = IngestOptions::default();
            let mut max_packets = Some(10_000u64);
            let packetcache = cmd == "packetcache";
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
            let case = match (packetcache, mode.as_str()) {
                (false, "listen") => {
                    capture::pcap_over_ip::ingest_listen(&addr, &out_dir, &opts, max_packets)?
                }
                (false, "connect") => {
                    capture::pcap_over_ip::ingest_connect(&addr, &out_dir, &opts, max_packets)?
                }
                (true, "listen") => {
                    capture::packetcache::ingest_listen(&addr, &out_dir, &opts, max_packets)?
                }
                (true, "connect") => {
                    capture::packetcache::ingest_connect(&addr, &out_dir, &opts, max_packets)?
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
        "write-sample-dbs" => {
            let dir = PathBuf::from(args.next().unwrap_or_else(|| "testdata/enrich".into()));
            hostsight::enrich::write_sample_dbs(&dir)?;
            println!("wrote sample DBs under {}", dir.display());
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

fn apply_decode_as(map: &mut DecodeAsMap, spec: &str) -> Result<()> {
    // tcp/8443=HTTPS or udp/53=DNS
    let (left, name) = spec
        .split_once('=')
        .context("--decode-as expects proto/port=Name")?;
    let (proto, port_s) = left
        .split_once('/')
        .context("--decode-as expects proto/port=Name")?;
    let port: u16 = port_s.parse()?;
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => {
            map.tcp.insert(port, name.to_string());
        }
        "udp" => {
            map.udp.insert(port, name.to_string());
        }
        _ => bail!("proto must be tcp or udp"),
    }
    Ok(())
}

fn print_usage() {
    eprintln!(
        "HostSight CLI\n\nCommands:\n  parse <file>   (pcap|pcapng|etl|dump)\n  carve <dump>\n  pcap-over-ip listen|connect <addr>\n  packetcache listen|connect <addr>  (HSPC magic + PCAP)\n  devices\n  write-sample-dbs [DIR]\n\nCommon flags: --out DIR --export-dir DIR --cidr CIDRS --decode-as tcp/443=HTTPS --no-defang\n"
    );
}
