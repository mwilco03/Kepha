# v5: Expand Fingerprinting Beyond JA4+ Passive TLS

## Summary

Gatekeeper currently has strong **passive TLS fingerprinting** (JA4/JA4S/JA4T/JA4H)
with live AF_PACKET capture, threat feed matching, anomaly detection, and IOC-driven
enforcement. This tracks expanding into the remaining fingerprinting technique families.

## What exists today

| Technique | Status | Implementation |
|-----------|--------|----------------|
| TLS ClientHello (JA4) | Done | `inspect/ja4.go` — cipher/ext ordering, GREASE filter, ALPN |
| TLS ServerHello (JA4S) | Done | `inspect/ja4.go` — negotiated cipher, extensions |
| TCP SYN (JA4T) | Done | `inspect/ja4.go` — window size, options, TTL, MSS, OS guess |
| HTTP Headers (JA4H) | Done | `inspect/ja4.go` — method, header order, cookie count, lang |
| Live packet capture | Done | `inspect/capture.go` — AF_PACKET, BPF filter, zero-copy |
| Threat feed matching | Done | `inspect/threatfeed.go` — O(1) merged index, 5 default feeds |
| Anomaly detection | Done | `inspect/anomaly.go` — fingerprint change tracking, severity escalation |
| IOC store + enforcement | Done | `inspect/iocstore.go` — IP/CIDR/ASN/domain/fingerprint IOCs → countermeasures |
| ASN resolution | Done | `inspect/asn.go` + `mmdb_updater.go` — DB-IP/MaxMind, auto-update |
| Device identification | Done | `inspect/ja4.go` — pattern matching with confidence scoring |

## What's missing

### Tier 1 — Passive, high value, no new dependencies

- [ ] **Banner grabbing** — Extract server banners from HTTP (`Server:` header),
  SSH (protocol version string), SMTP (`220` greeting). Passive: read from existing
  traffic, don't probe. Store as a new fingerprint type.
- [ ] **DNS query pattern fingerprinting** — Track query types, EDNS options, DNSSEC
  behavior per source IP. Identifies DNS tunneling, exfil, and resolver fingerprinting.
- [ ] **HTTP/2 SETTINGS frame fingerprinting** — `SETTINGS_HEADER_TABLE_SIZE`,
  `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE` ordering.
  Highly discriminating for browser/bot detection.
- [ ] **TLS certificate chain analysis** — Parse server certs from captured handshakes:
  issuer, validity, SAN list, key type/size. Flag self-signed, expired, or known-bad issuers.
- [ ] **TCP FIN/RST behavior** — How connections are torn down reveals OS and
  application stack. Track RST vs FIN, timing, and sequencing.

### Tier 2 — Passive, requires new capture paths

- [ ] **ICMP fingerprinting** — ICMP echo reply TTL, payload patterns, rate limiting
  behavior. Requires extending BPF filter beyond TCP 443.
- [ ] **Timing analysis** — Measure inter-packet arrival times, SYN-ACK latency,
  TLS handshake duration. Statistical profiling per source IP. Useful for detecting
  proxies, VPNs, and Tor exits.
- [ ] **Packet size distribution** — Track MTU, typical payload sizes, fragmentation
  behavior. Different OS/app stacks have distinct patterns.

### Tier 3 — External tool integration (passive ingestion)

- [ ] **Zeek log ingestion** — Parse `conn.log`, `ssl.log`, `http.log`, `dns.log`
  into IOCs and fingerprints. Zeek sees everything gatekeeper's BPF filter doesn't
  (non-TLS protocols, full HTTP, DNS).
- [ ] **Suricata alert correlation** — Ingest Suricata EVE JSON alerts as IOC source.
  Map rule SIDs to severity levels. Feed into countermeasure response templates.
- [ ] **p0f-style passive OS detection** — Implement the p0f signature database format
  natively in Go. Match TCP SYN/SYN+ACK against known OS signatures (more precise
  than JA4T TTL heuristics).
- [ ] **Arkime session enrichment** — Query Arkime's API to enrich fingerprint records
  with full session metadata (packet counts, byte counts, protocol analysis).

### Tier 4 — Active probing (opt-in, careful)

- [ ] **Behavioral fingerprinting** — Long-term behavioral baselines per IP/fingerprint:
  connection frequency, port diversity, time-of-day patterns, protocol mix. Statistical
  deviation triggers anomaly alerts.
- [ ] **Active banner probing** — Opt-in: connect to discovered services and grab banners.
  Must be explicitly enabled and rate-limited. Useful for internal network inventory.
- [ ] **Nmap-style OS detection** — Send crafted TCP/ICMP probes and match responses
  against Nmap's `nmap-os-db`. Requires explicit opt-in (active scanning). Only for
  internal/authorized networks.

## Design constraints

- **Passive by default** — No active probing without explicit opt-in (same pattern as
  countermeasures: disabled by default, requires `Enable()`)
- **No shell-outs** — All parsing in Go. External tools (Zeek, Suricata) are ingested
  via log files or APIs, never exec'd
- **Fast-path safe** — New fingerprint types must not add per-packet overhead to the
  enforcement path. Index first, match O(1)
- **Graceful degradation** — Each technique is independently optional. Capture failure
  doesn't break threat feeds. Zeek absence doesn't break JA4

## Non-goals

- ML/AI-based behavioral analysis (keep it deterministic and auditable)
- Full PCAP storage (that's Arkime's job)
- Active vulnerability scanning (that's Nmap/Nuclei's job, not a firewall's)
