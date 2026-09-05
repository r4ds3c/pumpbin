# Changelog

## 0.1.0 — HostSight pivot (Phase 0–4)

### Phase 0–1
- Rebranded from PumpBin to **HostSight** NFAT; removed implant/Maker/Extism
- PCAP/PcapNG → hosts/sessions/DNS/HTTP; iced tabs; CLI parse

### Phase 2
- TLS SNI/JA3/JA3S/JA4 + certs; FTP/TFTP/mail/SMB/HTTP2/LPR; tunnel decap; defang

### Phase 3
- Packet carver; Pcap-over-IP; live-capture feature; SIP/RTP→WAV; timezone

### Phase 4
- Offline GeoIP + ASN (CSV DBs); DNS whitelist; ad/tracker flags
- PIPI + decode-as; OS guess; host coloring; CIDR filter; browser tracing
- OSINT URL hooks (VirusTotal links; optional `HOSTSIGHT_OSINT_CMD`)
- Export CSV / Excel-CSV / XML / CASE / JSON-LD; CLI `--export-dir`
