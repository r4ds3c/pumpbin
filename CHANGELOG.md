# Changelog

## 0.1.0 — HostSight pivot (Phase 0–2)

### Phase 0–1
- Rebranded from PumpBin implant generator to **HostSight** NFAT
- Removed Maker, Cap’n Proto `.b1n`, Extism, implant examples
- iced GUI with NetworkMiner-style tabs; PCAP/PcapNG → hosts/sessions/DNS/HTTP
- `hostsight-cli parse`; Phase 1 fixture test

### Phase 2
- TLS handshake metadata: SNI, JA3, JA3S, JA4; X.509 cert extract to files
- Extractors: FTP, TFTP, SMTP/POP3/IMAP, SMB/SMB2 hints, HTTP/2 DATA, LPR
- Tunnel decap: VLAN/QinQ, GRE, VXLAN, PPPoE, MPLS
- UI/CLI toggle for executable defanging (default ON)
- Golden tests for FTP, TFTP, SMTP, HTTP, TLS
