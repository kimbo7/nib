# NIB Threat Model

## What NIB Is

NIB is a network intrusion detection and automated response system. It watches network traffic, matches packets against known attack signatures, detects behavioral patterns, and blocks offending IPs.

## What NIB Detects Well

| Category | How | Confidence |
|----------|-----|------------|
| **Port scans and service enumeration** | Suricata signatures + CrowdSec scan scenarios | High |
| **Brute force attacks** | CrowdSec behavioral detection (repeated failures) | High |
| **Known exploit attempts** | 40,000+ ET Open signatures matching CVE patterns | High |
| **Malware C2 callbacks** | Signatures for known C2 domains, IPs, and protocols | Medium-High |
| **Crypto mining traffic** | Stratum protocol detection, known pool addresses | High |
| **DNS anomalies** | DGA-like query patterns, NXDOMAIN floods | Medium |
| **Known-bad TLS fingerprints** | JA3/JA4 hash matching against threat intel | Medium |
| **Previously seen attackers** | CrowdSec community blocklist (millions of nodes) | Medium |

## What NIB Won't Detect

| Blind Spot | Why |
|------------|-----|
| **Encrypted payload content** | Suricata sees TLS metadata (SNI, JA3, certificate) but cannot inspect the encrypted payload without TLS termination. This is inherent to all passive IDS tools. |
| **Zero-day exploits** | Signature-based detection requires a known pattern. Novel exploits with no matching signature will pass through until rules are updated. |
| **Internal lateral movement** | Unless NIB is positioned to see east-west traffic (e.g., on a bridge interface or SPAN port mirroring internal segments), it only sees traffic crossing the monitored interface. |
| **Application-layer logic bugs** | Business logic flaws, IDOR, broken access control — these require application-level security, not network IDS. |
| **Low-and-slow attacks** | Attackers that stay below CrowdSec's behavioral thresholds may avoid automated blocking. |
| **Legitimate services on unusual ports** | Without protocol-aware context, some detections may misclassify legitimate traffic. |

## What "Blocking" Does and Doesn't Do

### What it does
- CrowdSec instructs the firewall bouncer to add `iptables DROP` rules for banned IPs
- In **local mode**, this drops traffic on the NIB host itself (effective when NIB runs on the target server or gateway)
- In **sensor mode**, bans are pushed to external routers/firewalls via API or native plugins
- Bans are time-limited (default: 4h generic, 24h for IDS-triggered) and automatically expire

### What it doesn't do
- NIB is **not an inline IPS** — it doesn't modify or drop packets in real-time as they pass through. It detects, then blocks the source IP after the fact. The first packets of an attack will reach the target.
- IP-based blocking has **collateral damage potential** with shared IPs (NAT gateways, CDNs, VPNs). A banned IP may block legitimate users behind the same NAT.
- Blocking is **reactive, not preventive** — it stops continued attacks from the same IP, not the initial exploit attempt.

## Trust Boundary: NIB Itself

NIB runs with elevated privileges:

| Component | Privileges | Risk |
|-----------|-----------|------|
| Suricata | `network_mode: host`, `NET_ADMIN`, `NET_RAW`, `SYS_NICE` | Can see all network traffic on the host |
| Firewall Bouncer | `network_mode: host`, `NET_ADMIN`, `NET_RAW` | Can modify iptables rules on the host |
| CrowdSec Engine | Network access to LAPI port | Controls blocking decisions |

**If NIB is compromised, an attacker could:**
- Read all network traffic (via Suricata's capture capabilities)
- Modify firewall rules (via the bouncer's iptables access)
- Disable blocking (by manipulating CrowdSec decisions)
- Use the host network position as a pivot point

### Mitigations applied
- All containers use `no-new-privileges: true` (prevents privilege escalation)
- All containers use `cap_drop: ALL` with only required capabilities added back:

| Container | Capabilities | Why |
|-----------|-------------|-----|
| nib-suricata | `NET_ADMIN`, `NET_RAW`, `SYS_NICE` | AF_PACKET capture, interface config, thread priority |
| nib-bouncer-firewall | `NET_ADMIN`, `NET_RAW` | iptables rule manipulation |
| nib-crowdsec | none | Runs unprivileged (reads logs, serves API) |
| nib-victorialogs | none | Runs unprivileged (log storage) |
| nib-vector | none | Runs unprivileged (log shipping) |
| nib-grafana | none | Runs unprivileged (dashboards) |

- Non-host-network containers run `read_only: true` with explicit `tmpfs` mounts
- VictoriaLogs and CrowdSec API bind to `127.0.0.1` by default
- Grafana has anonymous access and sign-up disabled
- CrowdSec bouncers authenticate via API key

### Additional recommendations
- Run NIB on a dedicated host or VM when possible
- Keep Docker and all images updated
- Monitor NIB container logs for unexpected behavior
- In sensor mode, restrict LAPI access to known bouncer IPs via firewall rules
- Run `make audit` periodically to verify security posture
