# Known Limitations

Practical issues you may encounter when running NIB. Understanding these upfront saves debugging time.

## WiFi Capture

Most WiFi drivers **do not support promiscuous mode**, which means Suricata on `wlan0` will only see traffic to/from the NIB host itself — not other devices on the network.

**Workaround**: Use a wired connection, or run NIB on a device with a wired connection to the network (router, server, switch with SPAN port).

## NIC Offloading

Modern NICs offload checksum calculation, segmentation, and receive coalescing to hardware. This can cause Suricata to:
- Report checksum errors on valid packets
- See aggregated "jumbo" packets instead of individual frames
- Miss packets that are coalesced before reaching userspace

**Fix**:
```bash
# Disable offloads on the capture interface
sudo ethtool -K eth0 rx off tx off gro off lro off gso off tso off

# Make persistent (add to /etc/network/interfaces or networkd config)
```

**How to tell**: If Suricata logs show many `stream.reassembly` or checksum anomalies, offloading is likely the cause.

## ET Open Rules — False Positives

The Emerging Threats Open ruleset contains 40,000+ signatures. Out of the box, some rules will generate false positives, especially:

- **Policy rules** (e.g., "ET POLICY" category) — flags behavior that isn't necessarily malicious (Tor usage, BitTorrent, VPN connections)
- **Info rules** — informational alerts about observed protocols, not attacks
- **Overly broad signatures** — rules matching common patterns that legitimate traffic also uses

**Recommendations**:
- Focus on `ET TROJAN`, `ET EXPLOIT`, `ET MALWARE`, and `ET SCAN` categories
- Use Suricata's threshold/suppress mechanism for noisy rules:
  ```yaml
  # In suricata/rules/threshold.config
  suppress gen_id 1, sig_id 2210000  # Suppress a specific noisy rule
  threshold gen_id 1, sig_id 2210001, type limit, track by_src, count 1, seconds 3600
  ```
- Set `HOME_NET` correctly — many false positives come from RFC1918 defaults matching traffic that isn't actually "home"

## IP-Based Blocking Collateral

CrowdSec blocks by IP address. This can cause collateral damage when:

- **Multiple users share an IP** (corporate NAT, ISP CGNAT, mobile carriers)
- **CDN IPs get flagged** — blocking a CDN exit node blocks all traffic from that CDN
- **VPN exit nodes** — legitimate users behind the same VPN server get blocked

**Mitigations**:
- Ban durations are time-limited (default 4h generic, 24h for IDS-triggered)
- Manual unban: `make unban IP=x.x.x.x`
- Whitelist known good IPs in CrowdSec:
  ```bash
  docker exec nib-crowdsec cscli parsers install crowdsecurity/whitelists
  ```
- Review decisions regularly: `make decisions`

## iptables Chain Ordering

The CrowdSec firewall bouncer creates a `crowdsec-blacklists` iptables chain and inserts rules into INPUT and FORWARD chains. If you already manage iptables/nftables:

- **Existing rules may conflict** — the bouncer inserts at the top of INPUT/FORWARD, which means its DROP rules take precedence over your ACCEPT rules
- **Firewall resets can remove bouncer rules** — if you run `iptables -F` or restart your firewall manager (ufw, firewalld), bouncer rules will be lost until the bouncer restarts
- **nftables compatibility** — the bouncer uses iptables (legacy). If your system uses nftables natively, the `iptables` commands use the nft backend, which usually works but can have edge cases

**Recommendations**:
- Check bouncer chain placement: `sudo iptables -L INPUT -n --line-numbers`
- If using ufw/firewalld, ensure the bouncer service starts after the firewall manager
- After firewall changes, restart the bouncer: `make restart` or `docker restart nib-bouncer-firewall`

## Encrypted Traffic

Suricata cannot inspect encrypted payloads (TLS/SSL content). It can:
- **See**: TLS handshake metadata (SNI, certificate info, JA3/JA4 fingerprints)
- **Not see**: The actual HTTP request/response inside the TLS tunnel

This means:
- HTTPS-based C2 channels with clean TLS fingerprints may evade detection
- Malware using encrypted DNS (DoH/DoT) to known-good resolvers won't be flagged by DNS rules
- File exfiltration over TLS won't be caught by content-matching rules

**Mitigation**: TLS fingerprinting (JA3/JA4) catches many malware families that use distinctive TLS libraries. Community blocklists add another layer. For deeper inspection, consider TLS termination at a proxy — but that's outside NIB's scope.

## Performance on High-Traffic Networks

On links above ~1 Gbps, Suricata in Docker may struggle to keep up:

- **AF_PACKET in Docker** has slightly higher overhead than bare-metal Suricata
- **All-rules-enabled** with full protocol logging is CPU-intensive
- **VictoriaLogs ingestion** may fall behind if EVE JSON output is very high volume

**Recommendations**:
- Use `PRIVACY_MODE=alerts-only` to reduce log volume
- Tune `af-packet` threads in `suricata.yaml` to match CPU cores
- Consider running Suricata natively (not in Docker) for >1 Gbps links
- Monitor with `make metrics` to see if Suricata reports dropped packets
