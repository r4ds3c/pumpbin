# Changelog

## 0.1.0 — HostSight pivot (Phase 0–3)

### Phase 0–1
- Rebranded from PumpBin implant generator to **HostSight** NFAT
- Removed Maker, Cap’n Proto `.b1n`, Extism, implant examples
- iced GUI with NetworkMiner-style tabs; PCAP/PcapNG → hosts/sessions/DNS/HTTP
- `hostsight-cli parse`; Phase 1 fixture test

### Phase 2
- TLS: SNI, JA3, JA3S, JA4; X.509 cert extract
- FTP, TFTP, SMTP/POP3/IMAP, SMB hints, HTTP/2 DATA, LPR
- Tunnel decap: VLAN/QinQ, GRE, VXLAN, PPPoE, MPLS
- Executable defang toggle

### Phase 3
- Network Packet Carver (memory/blob → frames)
- Pcap-over-IP listen/connect
- Live sniff feature flag (`live-capture` + Npcap/libpcap)
- SIP + RTP G.711 → WAV; VoIP Play opens system player
- Timezone display toggle (UTC / Local)
- CLI: `carve`, `pcap-over-ip`, `devices`
