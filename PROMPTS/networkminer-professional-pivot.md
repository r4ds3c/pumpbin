# Agent Brief: Full Pivot to NetworkMiner Professional–Class NFAT

Copy everything below the line into an agent session to execute this product pivot.

---

## Mission

Fully pivot this repository (**PumpBin**, currently an implant-generation GUI) into a **host-centric Network Forensic Analysis Tool (NFAT)** with **feature parity to NetworkMiner Professional**, as publicly documented by NETRESEC.

**Success** means an analyst can open PCAP/PcapNG/ETL (and live/carved/Pcap-over-IP feeds), get a host inventory, extract files/emails/credentials/images/VoIP/certs, use Pro-only intelligence (GeoIP, ASN, PIPI, OSINT, DNS whitelist, browser tracing, exports, CLI), and never encounter implant-generation, `.b1n`, Maker, or Extism shellcode workflows.

Reference (requirements source of truth — do not reverse-engineer binaries):

- https://www.netresec.com/?page=NetworkMiner
- https://www.netresec.com/files/NetworkMiner-Professional_Product-Specifications.pdf
- NETRESEC blog posts describing NetworkMiner Pro behavior (for UX semantics only)

## Constraints (non-negotiable)

1. **Full product pivot** — Delete or replace implant generation, `.b1n` Cap’n Proto plugins, Maker binary, Extism encrypt/upload hooks, placeholder binary patching, and related UI/assets. Update `Cargo.toml` description, README, and binaries to reflect the new product.
2. **Stack** — Keep **Rust** + **iced** desktop GUI. Primary targets: **Windows** and **Linux**; macOS best-effort. Prefer portable, local-first packaging (no required installer if feasible).
3. **Clean-room** — Implement from public specs and protocol knowledge. **Do not** copy NetworkMiner source, decompile `NetworkMiner.exe`, reuse proprietary icons, or ship the NetworkMiner trademark as this product’s name. Use an original product name/branding (rebrand PumpBin or pick a new name; document the choice in README).
4. **Local-only** — All case data and extracts stay on the end-user device. No cloud backends. Optional OSINT lookups are user-initiated and configurable.
5. **Defensive forensics only** — Passive sniffing, capture parsing, artifact extraction, inventory. No implant builders, C2, exploitation, or payload generation.
6. **TLS** — Extract handshake artifacts (certs, JA3/JA3S/JA4, SNI). **Do not** decrypt TLS application data inside the app. Document that decrypted feeds (e.g. PolarProxy-style MITM → cleartext PCAP / Pcap-over-IP) are the supported path for HTTPS file extraction.
7. **Safety** — Extracted executables may be malware. Default to **defanging** PE/ELF/Mach-O extracts (e.g. rename extension / neutralize headers) with a clear toggle. Warn in UI/docs about sandbox use when analyzing hostile traffic.

## Product identity and UX model

Build a **host-centric** tool (primary mental model = inventory of hosts and their artifacts), **not** a packet-list Wireshark clone.

### Case workflow

1. Create/open a case (or implicit case on first open).
2. Ingest: file(s), live sniff, Pcap-over-IP, PacketCache-style stream, or memory-dump carve.
3. Parse → reassemble → extract → aggregate into host-centric store.
4. Browse tabs; filter; color hosts; keyword search; VoIP playback.
5. Artifacts land in a **configurable output directory**.
6. Export selected/all views to CSV / Excel-friendly CSV / XML / CASE / JSON-LD.
7. Reload case files after keyword list changes (re-crawl semantics).

### Required UI surfaces (NetworkMiner-style tabs)

| Tab | Purpose |
|-----|---------|
| **Hosts** | Per-IP/host inventory: OS fingerprint, MAC/OUI vendor, hostnames, User-Agents, open ports, country/ASN, colors, sessions summary |
| **Files** | Reconstructed files with metadata; open folder / details / hash / OSINT |
| **Images** | Thumbnails of extracted images; jump to file details |
| **Messages** | Emails and chats (SMTP/IMAP/POP3/IRC/Oscar/SIP, etc.) |
| **Credentials** | Usernames/passwords, cookies, auth material from cleartext protocols |
| **Parameters** | Name/value pairs (HTTP query/POST/cookies, FTP commands, PcapNG comments, JSON params, etc.) |
| **DNS** | Queries/responses; whitelist hits; OSINT on names |
| **Sessions** | TCP/UDP session list (endpoints, ports, protocol, volumes) |
| **Keywords** | String and hex (`0x…`) search; matches with frame/session context; requires reload to re-scan |
| **Anomalies** | Parser/protocol anomalies worth analyst attention |
| **VoIP** | Call metadata; extracted audio; G.711 playback |

Also provide: open/clear/reload case, start/stop live capture, interface picker, CIDR filter, timezone setting, output directory setting, host coloring, export menus, and progress for long parses.

## Feature requirements — NetworkMiner Professional parity

Every item below is **required**. Items marked **[Pro]** are Professional-only on the Netresec comparison table; Free-tier items are still required because Pro includes them.

### Input and capture

| Requirement | Notes |
|-------------|--------|
| Live sniffing | Platform capture (Npcap/libpcap or equivalent); admin/capabilities as needed |
| Parse PCAP | Classic libpcap format |
| Parse **PcapNG** **[Pro]** | Required |
| Parse ETL | Windows `netsh trace` / `pktmon` ETL |
| **Network Packet Carver** **[Pro]** | Carve packets/frames from memory dumps / unstructured blobs |
| Receive **Pcap-over-IP** | TCP listen/connect for PCAP stream |
| Receive **PacketCache**-style feed | Accept compatible streamed capture if documented protocol is public; otherwise stub interface + PCAP file drop equivalent and document |
| IPv4 and IPv6 | Full support |

### Decapsulation

Support stripping/decoding at least: **GRE, 802.1Q, PPPoE, VXLAN, OpenFlow, SOCKS, MPLS, EoMPLS, ERSPAN**. Phased stretch: **GTP, CAPWAP, TZSP** (appear in NetworkMiner changelogs).

### File and message extraction

Reassemble and extract files from at least:

**FTP, TFTP, HTTP, HTTP/2, SMB, SMB2, SMTP, POP3, IMAP, LPR, IEC-104, njRAT**

Also extract messages/content from:

**SMTP, IMAP, POP3, IRC, Oscar, SIP** (and other chat/email sources NetworkMiner documents)

Phased stretch extractors from public changelogs (implement as capacity allows, prioritize by IR usefulness): Meterpreter payloads, VNC/BackConnect artifacts, StealC, Remcos, Modbus/TCP, CIP/UMAS, QUIC metadata where practical, DoH, Kerberos usernames, etc.

### TLS / crypto metadata (not decryption)

- Extract **X.509** certificates from SSL/TLS handshakes (HTTPS, SMTPS, IMAPS, POP3S, FTPS, etc.)
- **JA3, JA3S, JA4** fingerprints
- **SNI** and related ClientHello fields useful for inventory

### VoIP **[Pro]**

- Audio extraction from **SIP+RTP** (G.711, G.722)
- Audio extraction from **RTP without SIP** (G.711, G.722)
- **Playback** of VoIP calls (**G.711**) in-app

### Host inventory and asset ID

- Passive **OS fingerprinting** (p0f / Satori-class signature DBs; ship or downloadable DB with license compliance)
- **Advanced OS fingerprinting** **[Pro]**
- **NIC vendor** identification (MAC OUI)
- **Hostname** extraction (DNS, NetBIOS, DHCP, banners, etc.)
- Browser **User-Agent** extraction
- **Open ports** observed per host
- **Host coloring** **[Pro]**
- **CIDR filter** **[Pro]**

### Intelligence and enrichment **[Pro]**

- **OSINT lookups** for file hashes, IP addresses, domain names, URLs (pluggable providers; offline-first UI)
- **Offline IP-to-country** lookup
- **Offline IP ASN** lookup
- **DNS whitelisting** against a top-sites list (Alexa top 1M–class or maintained equivalent; document source/update)
- **Advertisement and tracker detection**
- **Port Independent Protocol Identification (PIPI)** — identify protocols regardless of port (at least: DNS, FTP, HTTP, HTTP/2, IRC, Meterpreter, NetBIOS NS/SS, SOCKS, Spotify server protocol, SSH, SSL/TLS, TDS/MS-SQL, TPKT)
- **User-defined port→protocol mappings** (“decode as”)
- **Web browser tracing** — reconstruct browsing path from HTTP(S cleartext) for visualization/investigation

### Keywords and parameters

- Keyword tab: case-sensitive strings and hex byte patterns; match list with frame/session context
- Changing keywords does **not** auto-rescan; **Reload** re-crawls already loaded traffic
- Parameters: HTTP query/POST/cookies, FTP commands, JSON-ish name/values, PcapNG packet comments, etc.

### Export, settings, CLI

| Requirement | Notes |
|-------------|--------|
| Export **CSV / Excel-friendly** **[Pro]** | Hosts, files, sessions, DNS, credentials, parameters, keywords, etc. |
| Export **XML** **[Pro]** | |
| Export **CASE** **[Pro]** | Cyber-investigation Analysis Standard Expression |
| Export **JSON-LD** **[Pro]** | |
| Configurable **file output directory** **[Pro]** | |
| Configurable **timezone** (UTC / local / custom) **[Pro]** | |
| **CLI scripting** **[Pro]** | Second binary (NetworkMinerCLI analogue): batch open captures, extract, export, exit codes suitable for scripts |

### Cross-platform

- Runs on **Windows and Linux** (GUI). Document live-sniff limitations per OS (e.g. privileges, Npcap).

## Architecture to implement

```text
Inputs (PCAP | PcapNG | ETL | Live | Carve | Pcap-over-IP)
        → Packet decode + tunnel decap
        → TCP/UDP reassembly / flow tracking
        → Protocol extractors (modular)
        → Case store (host-centric aggregation)
        → iced UI tabs  |  Export  |  CLI
```

### Suggested crate / module layout (adapt as needed)

```text
src/
  main.rs              # GUI binary entry
  lib.rs               # App state, iced update/view
  case/                # Case model, persistence, output paths
  capture/             # File readers, live sniff, pcap-over-IP, carver
  decode/              # Link/network/transport, decap tunnels
  reassembly/          # Streams, sessions
  proto/               # One module per protocol family (http, smb, dns, …)
  extract/             # Files, certs, messages, voip, credentials
  fingerprint/         # OS, JA3/JA4, PIPI, OUI
  enrich/              # GeoIP, ASN, DNS whitelist, trackers, OSINT adapters
  export/              # CSV, XML, CASE, JSON-LD
  ui/                  # Tabs, filters, themes, dialogs
bin/
  <product>-cli.rs     # Scripting CLI
```

Candidate libraries (choose pragmatically; replace if better): `pcap`/`npcap` bindings, `etherparse` or similar, `tokio` for async I/O (already used via iced), `x509-parser`, RTP/SIP crates or hand-rolled minimal parsers, MaxMind-style local DBs for Geo/ASN (respect licenses).

Remove obsolete: Cap’n Proto plugin schema, Extism, Maker, implant examples that only serve shellcode injection demos (or move clearly labeled sample PCAPs for forensics tests instead).

### Binaries

| Binary | Role |
|--------|------|
| GUI (replace `pumpbin` default-run) | Analyst UI |
| CLI (replace or retire `maker`) | Headless parse/extract/export |

## Implementation phases (ship incremental value)

### Phase 0 — Pivot scaffolding

- Strip implant/Maker/`.b1n`/Extism paths from the build.
- New iced shell with empty tabs + case open dialog.
- README rewritten for NFAT mission.
- **Done when:** app launches as forensics shell; old generation flows gone from UI and `cargo build` has no Extism/capnp plugin deps unless reused for something else (prefer remove).

### Phase 1 — MVP (Free-tier core)

- PCAP (+ ETL if feasible early) ingest; IPv4/IPv6; basic sessions.
- Hosts / Sessions / DNS / Files (HTTP + DNS minimum) / Credentials (HTTP Basic/FTP) / Parameters / Keywords / Anomalies stubs.
- TCP reassembly for HTTP file extract; image thumbnails for common image MIME/types.
- **Done when:** opening a public sample PCAP populates Hosts, Sessions, DNS, and extracts at least one HTTP file.

### Phase 2 — Broad extractors + TLS metadata

- SMB/SMB2, FTP/TFTP, mail (SMTP/POP3/IMAP), HTTP/2, LPR, IEC-104; messages tab; X.509 + JA3/JA3S/JA4 + SNI; certificates as files.
- Decapsulation: VLAN, GRE, VXLAN, at least two more tunnels from the required list.
- Defang option for executables.
- **Done when:** golden-file tests exist for ≥5 protocol extractors; certs appear for a TLS-handshake PCAP.

### Phase 3 — Professional capture & VoIP

- **PcapNG**, Packet Carver, Pcap-over-IP, live sniff polish, PacketCache-compatible input or documented substitute.
- VoIP extract + G.711 playback UI.
- Configurable output dir + timezone.
- **Done when:** PcapNG and a carved dump each yield hosts/files; one SIP/RTP fixture produces playable audio.

### Phase 4 — Professional intelligence & export

- Offline GeoIP + ASN; DNS whitelist; ad/tracker detection; host coloring; CIDR filter.
- PIPI + user decode-as maps; advanced OS fingerprinting; browser tracing view.
- OSINT provider hooks (hash/IP/domain/URL).
- Export CSV/XML/CASE/JSON-LD; CLI binary with scripting examples.
- **Done when:** checklist below is all checked; CLI exports match GUI counts on a fixture set.

## Acceptance checklist (must all pass before calling Pro parity “done”)

### Capture / input

- [ ] Live sniffing
- [ ] PCAP
- [ ] PcapNG **[Pro]**
- [ ] ETL
- [ ] Network Packet Carver **[Pro]**
- [ ] Pcap-over-IP
- [ ] PacketCache-style or documented equivalent
- [ ] IPv4 + IPv6

### Decap / protocols

- [ ] GRE, 802.1Q, PPPoE, VXLAN, OpenFlow, SOCKS, MPLS, EoMPLS, ERSPAN
- [ ] File extract: FTP, TFTP, HTTP, HTTP/2, SMB, SMB2, SMTP, POP3, IMAP, LPR (+ IEC-104, njRAT)
- [ ] Messages: SMTP, IMAP, POP3, IRC, Oscar, SIP
- [ ] X.509 from TLS; JA3; JA3S; JA4; SNI
- [ ] PIPI **[Pro]** + user port-protocol maps **[Pro]**

### Artifacts / UI

- [ ] Hosts inventory with OS fingerprint (basic + advanced **[Pro]**), OUI, hostnames, UA, open ports
- [ ] Files, Images, Messages, Credentials, Parameters, DNS, Sessions, Keywords, Anomalies, VoIP **[Pro]**
- [ ] VoIP extract SIP+RTP and RTP-only (G.711/G.722); G.711 playback **[Pro]**
- [ ] OSINT lookups **[Pro]**
- [ ] Offline IP→country **[Pro]**; offline ASN **[Pro]**
- [ ] DNS whitelisting **[Pro]**; ad/tracker detection **[Pro]**
- [ ] Host coloring **[Pro]**; CIDR filter **[Pro]**; browser tracing **[Pro]**
- [ ] Configurable output directory **[Pro]**; timezone UTC/local/custom **[Pro]**
- [ ] Export CSV/Excel, XML, CASE, JSON-LD **[Pro]**
- [ ] CLI scripting binary **[Pro]**
- [ ] Windows + Linux GUI runs
- [ ] Executable defanging option
- [ ] No implant-generation code paths remain

## Testing strategy

- Maintain a `testdata/` set of **small public PCAPs** (and at least one PcapNG, one ETL if available, one memory blob for carver).
- Golden extracts: expected filenames/hashes, credential rows, DNS Q/R counts, JA3 strings.
- Fuzz decoders carefully (untrusted captures); never execute extracted binaries in CI.
- Performance: aim for responsive UI on multi-hundred-MB captures (background parse + progress); document limits.

## Out of scope / ethics

- Reproducing NetworkMiner’s proprietary code, licensing system, or trademarks.
- TLS active decryption inside the product.
- Any return of PumpBin implant generation, shellcode injection, or Maker plugin authoring for malware delivery.
- Shipping commercial OSINT API keys; use env/config for optional providers.

## Working style for the implementing agent

- Prefer incremental PRs/commits by phase; keep the tree buildable after each phase.
- Match existing iced patterns where they still apply (themes, `rfd` dialogs, tokio); delete dead code rather than leaving stubs of the old product.
- Do not add unsolicited markdown docs beyond README + this prompt’s required operator notes.
- When a Netresec Pro behavior is ambiguous, prefer documented blog/user-guide semantics and note assumptions in code comments briefly.

## First actions

1. Inventory and remove implant/Maker/plugin generation code from the crate.
2. Stand up iced NFAT shell with the tab list above.
3. Implement Phase 1 PCAP→Hosts/Sessions/DNS/HTTP files path with one fixture test.
4. Continue phases until the acceptance checklist is complete.
