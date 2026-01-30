# Production Checklist

Use this checklist before running NIB in production. Copy it to your notes and check off items as you go.

## Network Configuration

- [ ] **Set `SURICATA_INTERFACE`** to the correct network interface
  ```bash
  # Find your interfaces
  ip link show
  # Set in .env
  SURICATA_INTERFACE=eth0
  ```

- [ ] **Set `HOME_NET`** to your actual internal network ranges (not just RFC1918 defaults)
  ```bash
  HOME_NET=[192.168.1.0/24,10.0.0.0/8]
  ```

- [ ] **Disable NIC offloading** if Suricata reports checksum errors or missing packets
  ```bash
  # Check current offload settings
  ethtool -k eth0 | grep -E 'rx-checksumming|tx-checksumming|generic-receive-offload|large-receive-offload'

  # Disable offloads that interfere with capture
  sudo ethtool -K eth0 rx off tx off gro off lro off
  ```

## Security

- [ ] **Verify Grafana password** is not the default
  ```bash
  grep GRAFANA_ADMIN_PASSWORD .env
  # Should show an auto-generated password, not CHANGE_ME
  ```

- [ ] **Run `make audit`** and resolve any warnings
  ```bash
  make audit
  ```

- [ ] **Set `PRIVACY_MODE`** based on your data sensitivity requirements
  ```bash
  # Full protocol metadata (DNS, HTTP, TLS) — more visibility, more sensitive data
  PRIVACY_MODE=full

  # Alerts only — no protocol metadata logged
  PRIVACY_MODE=alerts-only
  ```

- [ ] **For sensor mode**: restrict LAPI access
  ```bash
  # Bind to specific interface instead of 0.0.0.0
  CROWDSEC_API_BIND=192.168.1.10

  # Firewall LAPI port to only allow bouncer IPs
  sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.1 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
  ```

## CrowdSec

- [ ] **Enroll in CrowdSec community** for pre-emptive blocklists
  ```bash
  # Register at https://app.crowdsec.net
  CROWDSEC_ENROLL_KEY=your-key-here
  ```

- [ ] **Verify bouncer is connected** (local mode)
  ```bash
  make bouncer-status
  ```

## Detection Rules

- [ ] **Test rule syntax** after any rule changes
  ```bash
  make test-rules
  ```

- [ ] **Set up automated rule updates** via cron
  ```bash
  # Update ET Open rules daily at 3 AM
  0 3 * * * cd /path/to/nib && make update-rules && make reload-rules
  ```

- [ ] **Review custom rules** in `suricata/rules/custom.rules`

## Storage & Retention

- [ ] **Set retention period** based on available disk space
  ```bash
  # Default: 7 days
  VICTORIALOGS_RETENTION=168h

  # 30 days (requires more disk)
  VICTORIALOGS_RETENTION=720h
  ```

- [ ] **Monitor disk usage** periodically
  ```bash
  docker system df
  ```

## Verification

- [ ] **Test the full pipeline** end-to-end
  ```bash
  # Trigger a test alert
  make test-alert

  # Wait 30 seconds, then check
  make logs-alerts
  make decisions
  ```

- [ ] **Verify Grafana dashboards** are populated
  ```bash
  make open
  ```

## Ongoing

- [ ] Run `make audit` after configuration changes
- [ ] Update rules regularly (`make update-rules`)
- [ ] Monitor `make health` for service issues
- [ ] Review CrowdSec decisions periodically (`make decisions`)
- [ ] Keep Docker images updated
