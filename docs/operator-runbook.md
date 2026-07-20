# RedOPS Active Chain Operator Runbook

> **Purpose**: Step-by-step guide for authorized operators executing the
> RedOPS Active Chain on a home lab or explicitly authorized target network.

## Pre-Flight Checklist

Before running any active module, verify every item below:

- [ ] I have **written authorization** for the target network, or the network
      is my own property / a designated isolated lab.
- [ ] The target network is **physically isolated** from production systems,
      guest networks, and internet-facing infrastructure.
- [ ] I have the required **hardware**:
  - Alfa AWUS036NHA or compatible monitor-mode-capable USB Wi-Fi adapter
  - A second Wi-Fi interface (built-in or USB) for control/management
  - Kali Linux or a distribution with `aircrack-ng`, `hostapd`, `dnsmasq`, `nmap`,
    `arp-scan`, and Python 3.12+
- [ ] I have **backups** of any data on the target network.
- [ ] I have informed any **other users** of the lab network that testing is
      scheduled and they may experience brief disconnections.
- [ ] I have reviewed `docs/legal-boundaries.md` and confirmed my use case
      falls within the authorized-use definition.

## Environment Setup

### 1. Hardware Verification

```bash
# Verify adapter is recognized
lsusb | grep -i rtl8187

# Verify monitor mode support
sudo airmon-ng check kill
sudo airmon-ng start wlan1
iwconfig | grep -i monitor
```

Expected output: `Mode:Monitor` for `wlan1mon`.

### 2. Software Verification

```bash
# Verify required tools
which airodump-ng hostapd dnsmasq nmap arp-scan
python -c "import scapy.all; print('scapy OK')"
```

### 3. Network Isolation Check

```bash
# Confirm no routes to external networks
ip route | grep default
# Should show only your management interface, not the lab interface
```

## Authorization Recording

The Active Chain **will not execute** without a recorded authorization. Create
one programmatically or via the API:

```python
from redops.core.context import Context
from redops.modules.active.authorization import record_authorization

ctx = Context(target="192.168.99.0/24")
record_authorization(
    ctx,
    operator="your-name",
    target_assertion="192.168.99.0/24 (home lab VLAN 99)",
    consent_text=(
        "I am authorized to perform active security testing on the stated target. "
        "This is my own network..."
    ),
    duration_hours=4,
)
```

**Mandatory fields**:
- `operator`: Your identity (name, employee ID, or operator handle).
- `target_assertion`: The exact target(s) you are authorized to test.
- `consent_text`: The full consent text you acknowledge.
- `duration_hours`: How long the authorization remains valid (default 24h).

## Execution Walkthrough

### Phase 1: Passive Reconnaissance

```python
from redops.modules.active.wireless.scan import scan_access_points

ctx = scan_access_points(ctx, {"duration": 30})
aps = ctx.get("access_points", [])
print(f"Discovered {len(aps)} access points")
```

**Expected behavior**: Passive scan only; no frames are injected.

### Phase 2: Target Selection

Select a target AP that you **own or have explicit permission to test**.
Record the BSSID, ESSID, and channel.

```python
target = aps[0]  # Example: select first AP
ctx.add("target_bssid", target["bssid"])
ctx.add("target_essid", target["essid"])
ctx.add("target_channel", target["channel"])
```

### Phase 3: Evil Twin Deployment

```python
from redops.modules.active.wireless.evil_twin import start_evil_twin

ctx = start_evil_twin(ctx, {
    "target_bssid": target["bssid"],
    "ap_interface": "wlan0",
})
```

**Warning**: This creates a functional rogue AP. Ensure it is on an isolated
channel and does not interfere with neighboring networks.

### Phase 4: Deauthentication (Optional)

```python
from redops.modules.active.wireless.deauth import deauth_flood

ctx = deauth_flood(ctx, {"duration": 30, "count": 64})
```

**Warning**: This actively disconnects clients from the legitimate AP. Only
run if you have explicit authorization and have warned any legitimate users.

### Phase 5: Host Discovery

```python
from redops.modules.active.network.arp_scan import discover_hosts

ctx = discover_hosts(ctx, {"wait": 15})
hosts = ctx.get("live_hosts", [])
print(f"Discovered {len(hosts)} live hosts")
```

### Phase 6: Port Scanning

```python
from redops.modules.active.network.port_scan import scan_ports

ctx = scan_ports(ctx, {"ports": "T:1-1024", "timing": "T4"})
results = ctx.get("port_scan_results", [])
```

### Phase 7: CVE Cross-Reference

```python
from redops.modules.active.exploit.cve_check import check_cves

ctx = check_cves(ctx)
findings = ctx.get("cve_findings", [])
```

## Teardown

### 1. Disable Monitor Mode

```python
from redops.modules.active.wireless.monitor import disable_monitor_mode

ctx = disable_monitor_mode(ctx)
```

### 2. Stop Rogue AP Processes

```python
import subprocess
subprocess.run(["sudo", "killall", "hostapd", "dnsmasq"], capture_output=True)
```

### 3. Restore Network Manager

```bash
sudo systemctl restart NetworkManager
```

### 4. Verify Cleanup

```bash
# Confirm no monitor interfaces remain
iwconfig | grep -i monitor || echo "No monitor interfaces"
# Confirm no hostapd/dnsmasq processes
pgrep -a hostapd || echo "hostapd not running"
pgrep -a dnsmasq || echo "dnsmasq not running"
```

## Lab Hardware Smoke Test

Before trusting RedOPS on a live engagement, validate the full chain in a
controlled lab:

| Step | Check | Pass Criteria |
|---|---|---|
| 1 | Adapter in monitor mode | `iwconfig` shows `Mode:Monitor` |
| 2 | AP scan | Discovers ≥1 test AP |
| 3 | Evil twin start | Client can see cloned SSID |
| 4 | Deauth flood | Clients disconnected from original AP within 10s |
| 5 | ARP scan | Discovers all expected lab hosts |
| 6 | Port scan | nmap completes without errors |
| 7 | CVE check | Returns findings for known vulnerable services |
| 8 | Authorization enforcement | `assert_active_authorized` raises without auth |
| 9 | Egress blocking | Cloud API call raises `EgressBlockedError` |
| 10 | Audit log | JSONL file contains all actions with timestamps |

## Post-Session Review

1. Export the audit log:
   ```bash
   cat output/audit.log | jq 'select(.action | startswith("active"))'
   ```
2. Review findings for false positives.
3. Document any deviations from the authorized scope.
4. Archive the session context and authorization record for compliance.

## Emergency Stop

If at any point you need to abort:

```bash
sudo airmon-ng stop wlan1mon
sudo killall -9 hostapd dnsmasq airodump-ng
sudo systemctl restart NetworkManager
```

## Support

For questions about authorized use, scope validation, or authorization
recording, open a discussion (not an issue) in the RedOPS GitHub repository.
For security vulnerabilities in the authorization mechanism itself, see
`SECURITY.md`.
