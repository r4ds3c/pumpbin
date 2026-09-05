# HostSight

**HostSight** is a host-centric Network Forensic Analysis Tool (NFAT) built with Rust and [iced](https://github.com/iced-rs/iced).

This repository previously shipped **PumpBin**, an implant-generation GUI. It has been fully pivoted to defensive network forensics. Implant generation, `.b1n` plugins, Maker, and Extism shellcode workflows are removed.

HostSight aims for feature parity with capabilities publicly documented for [NetworkMiner Professional](https://www.netresec.com/?page=NetworkMiner) (NETRESEC). It is a **clean-room** implementation from public specs and protocol knowledge — not affiliated with, endorsed by, or derived from NETRESEC source or binaries.

## Features (current)

Phases 0–5 (NetworkMiner Pro–class core + checklist stretch):

- Captures: PCAP, PcapNG, ETL (carve), carver, Pcap-over-IP, PacketCache `HSPC`; optional live (`--features live-capture`)
- Tunnels: VLAN, GRE/ERSPAN, VXLAN, PPPoE, MPLS, OpenFlow, SOCKS5
- Extractors: HTTP/2, FTP, TFTP, mail, SMB2 READ, LPR, TLS metadata, VoIP G.711; IRC/OSCAR/IEC-104/njRAT hints
- Intelligence: offline GeoIP/ASN, DNS whitelist, trackers, PIPI, decode-as, OS guess, browser trail
- UI: host colors, CIDR filter, OSINT buttons, Export all, VoIP Play; TZ UTC/Local/custom
- Exports: CSV, Excel-CSV, XML, CASE, JSON-LD (`hostsight-cli parse … --export-dir DIR`)

Remaining gaps vs the full Pro checklist (deeper ETW, GTP/CAPWAP, richer live UI, etc.) are still incremental.

See `PROMPTS/networkminer-professional-pivot.md` for the full checklist.

## Safety

- **Local-only** case data; no cloud backend
- **No TLS decryption** inside the app (use cleartext feeds such as PolarProxy → PCAP)
- Extracted binaries may be malware; PE/ELF/Mach-O extracts are **defanged** by default
- Analyze hostile traffic in a sandbox

## Build

```bash
cargo build --release
cargo test
cargo run --bin hostsight
cargo run --bin hostsight-cli -- parse path/to/capture.pcap --out ./out --export-json case.json
```

Windows and Linux are primary targets; macOS is best-effort.

## License

MIT
