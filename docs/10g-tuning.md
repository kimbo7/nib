# 10 Gbps Suricata Tuning Guide

At 10 Gbps, Suricata needs careful tuning to avoid packet drops. The defaults in NIB's `suricata.yaml` (threads: auto, ring-size: 2048, cluster_flow) work well up to ~1-2 Gbps but won't keep up at 10G.

This guide covers the host-level and Suricata-level changes needed. Since NIB runs Suricata in `network_mode: host`, all NIC tuning happens on the host directly — Docker doesn't add a network layer.

## Prerequisites

- 16+ CPU cores, 32 GB+ RAM (see README hardware sizing table)
- A server-grade NIC with multi-queue support:
  - **Intel**: X520, X540, X710, XXV710 (i40e/ixgbe drivers)
  - **Mellanox**: ConnectX-3, ConnectX-4, ConnectX-5 (mlx4/mlx5 drivers)
  - Avoid consumer NICs (Realtek, etc.) — they lack hardware RSS and queue depth
- Latest NIC firmware and kernel driver

## 1. Disable NIC Offloads

Offloading features interfere with Suricata's packet inspection (see also [known-limitations.md](known-limitations.md#nic-offloading)).

```bash
# Replace eth0 with your capture interface
sudo ethtool -K eth0 rx off tx off gro off lro off gso off tso off sg off
```

Make this persistent via a systemd unit or `/etc/network/interfaces` post-up hook.

## 2. Increase NIC Ring Buffers

Default ring buffers are too small for 10G burst traffic. Increase them to reduce kernel-level drops:

```bash
# Check current/max values
sudo ethtool -g eth0

# Set to maximum (or at least 4096-8192)
sudo ethtool -G eth0 rx 8192 tx 8192
```

## 3. Configure RSS (Receive Side Scaling)

RSS distributes incoming packets across multiple NIC queues, which Suricata can then process in parallel. Set the number of queues to match your Suricata worker thread count.

```bash
# Set combined queues (e.g., 16 for a 16-core system)
sudo ethtool -L eth0 combined 16

# Enable RSS hashing
sudo ethtool -K eth0 rxhash on
sudo ethtool -K eth0 ntuple on

# Use symmetric hashing key (ensures both directions of a flow go to the same queue)
sudo ethtool -X eth0 hkey \
  6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:\
  6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:\
  6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:\
  6D:5A:6D:5A equal 16

# Use Toeplitz hash function
sudo ethtool -X eth0 hfunc toeplitz

# Enable 4-tuple flow hashing (src/dst IP + src/dst port)
for proto in tcp4 udp4 tcp6 udp6; do
  sudo ethtool -N eth0 rx-flow-hash "$proto" sdfn
done
```

## 4. Pin IRQ Affinity

Each NIC queue generates interrupts. Pin them to specific CPUs so the CPU receiving the packet is the same one running the Suricata worker thread for that queue.

```bash
# Stop the system IRQ balancer (it fights your pinning)
sudo systemctl stop irqbalance
sudo systemctl disable irqbalance

# Intel NICs: use the driver's set_irq_affinity script
# (found in the driver source package or /usr/local/sbin/)
sudo set_irq_affinity local eth0

# Or manually pin IRQs to specific CPUs:
# Find IRQ numbers for your NIC
grep eth0 /proc/interrupts

# Pin each IRQ to a specific CPU (example for IRQ 48 -> CPU 2)
echo 2 | sudo tee /proc/irq/48/smp_affinity_list
```

## 5. Update Suricata Configuration

Edit `suricata/config/suricata.yaml` (the template — not `active-suricata.yaml`).

### AF_PACKET settings

Replace the default `af-packet` block:

```yaml
af-packet:
  - interface: default
    threads: 16                  # Match your RSS queue count
    cluster-id: 99
    cluster-type: cluster_qm    # Queue-mapping mode (requires RSS)
    defrag: no                   # Let Suricata handle defrag in workers
    use-mmap: yes
    mmap-locked: yes             # Lock mmap'd ring in memory
    tpacket-v3: yes
    ring-size: 100000            # Up from default 2048
    block-size: 1048576          # 1 MB blocks (up from 32 KB)
```

**`cluster_qm` vs `cluster_flow`**: `cluster_qm` (queue-mapping) pairs each Suricata thread with an RSS queue. This is more efficient than `cluster_flow` (kernel-level flow hashing) because the NIC hardware already distributed traffic. Use `cluster_qm` when RSS is properly configured; fall back to `cluster_flow` if RSS isn't available.

### CPU affinity

Enable CPU pinning so Suricata workers stay on the cores handling their NIC queues:

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]              # Management on CPU 0
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "1-16" ]         # Workers on CPUs 1-16 (match your thread count)
        mode: "exclusive"
        prio:
          high: [ "1-16" ]
          default: "high"
```

### Run mode

Ensure workers mode is set (this is the default in Suricata 7.x):

```yaml
runmode: workers
```

## 6. NUMA Considerations

On multi-socket servers, keeping the NIC and Suricata on the same NUMA node is critical. Cross-NUMA memory access adds significant latency.

```bash
# Check which NUMA node your NIC is on
cat /sys/class/net/eth0/device/numa_node

# Check NUMA topology
lscpu | grep NUMA

# Example: NIC on NUMA node 1, CPUs 18-35 and 54-71
# -> Set worker-cpu-set to those ranges
# -> Pin IRQs to the same ranges
```

Avoid CPU 0 for Suricata workers — it handles kernel housekeeping and interrupts from other devices.

## 7. NIB-Specific Notes

**Applying config changes**: Edit the template `suricata/config/suricata.yaml`, then reinstall:

```bash
make stop-suricata
make install-suricata
```

**Reduce log volume**: At 10G, EVE JSON output can be massive. Consider `PRIVACY_MODE=alerts-only` in `.env` to ship only alerts and stats to VictoriaLogs, reducing disk I/O and storage load.

**Docker overhead**: NIB uses `network_mode: host`, so there is no Docker network bridge in the packet path. The main Docker overhead is filesystem I/O for EVE JSON logging. Mount the log volume on fast storage (NVMe).

**Consider native Suricata**: For sustained 10G+ with full protocol logging, running Suricata natively (outside Docker) eliminates container overhead entirely. NIB's CrowdSec, Vector, and Grafana stacks can still run in Docker — they only need access to the EVE JSON log file.

## 8. Verifying Your Setup

### Check for packet drops

```bash
# Suricata's internal drop stats
make shell-suricata
suricatasc -c "iface-stat default"

# Look for capture.kernel_drops in stats
grep -i drop /var/log/suricata/stats.log | tail -5

# NIC-level drops
ethtool -S eth0 | grep -i drop
```

### Check thread balance

Watch for uneven load distribution:

```bash
# In eve.json stats events, check per-thread packet counts
# High stream.wrong_thread or tcp.pkt_on_wrong_thread values
# indicate RSS/affinity misconfiguration
grep wrong_thread /var/log/suricata/stats.log
```

### Monitor CPU usage

```bash
# Each Suricata worker should show similar CPU usage
# Uneven distribution means RSS hashing is skewed
htop  # Look for W#01-suricata, W#02-suricata, etc.
```

## References

- [Suricata High Performance Configuration](https://docs.suricata.io/en/suricata-7.0.2/performance/high-performance-config.html) — official guide with per-platform examples
- [Suricata, to 10Gbps and beyond](https://home.regit.org/2012/07/suricata-to-10gbps-and-beyond/) — foundational blog post by Eric Leblond
