# HostSight

**HostSight** is a host-centric Network Forensic Analysis Tool (NFAT) built with Rust and [iced](https://github.com/iced-rs/iced).

This repository previously shipped **PumpBin**, an implant-generation GUI. It has been fully pivoted to defensive network forensics. Implant generation, `.b1n` plugins, Maker, and Extism shellcode workflows are removed.

HostSight aims for feature parity with capabilities publicly documented for [NetworkMiner Professional](https://www.netresec.com/?page=NetworkMiner) (NETRESEC). It is a **clean-room** implementation from public specs and protocol knowledge — not affiliated with, endorsed by, or derived from NETRESEC source or binaries.

## Features (current)

Phase 0–3:

- Open **PCAP** / **PcapNG**; **carve** memory dumps; **Pcap-over-IP**
- Host inventory, sessions, DNS, HTTP/HTTP2, FTP, TFTP, mail, SMB hints, LPR
- TLS: SNI, JA3/JA3S/JA4, certificates (no decryption)
- VoIP: SIP + RTP G.711 → WAV with Play
- Tunnel peel: VLAN, GRE, VXLAN, PPPoE, MPLS
- Defang toggle; timezone UTC/Local; configurable output dir
- CLI: `parse`, `carve`, `pcap-over-ip`, `devices`
- Optional live capture: `cargo build --features live-capture` (Npcap/libpcap)

Phase 4 next: GeoIP/ASN, PIPI, OSINT, full export suite — see `PROMPTS/networkminer-professional-pivot.md`.

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
