# RedOps Mobile Wireless Audit Kit

Portable AI-Assisted Wireless Audit Platform\
Generated: 2026-02-21T23:16:52.419402 UTC

------------------------------------------------------------------------

## System Purpose

Convert a legacy 11" MacBook Air (Intel 1.4GHz) into a portable,
structured, legally compliant wireless analysis and RF survey platform.

This system is designed for: - Authorized wireless audits - RF mapping
and propagation testing - Structured documentation workflows -
AI-assisted utility scripting

------------------------------------------------------------------------

# Hardware Stack

## Core System

-   11" MacBook Air (Intel)
-   Kali Linux (XFCE)
-   4--8GB RAM
-   SSD (128GB+)

## Wireless Interface

-   Alfa adapter (AWUS036NHA / AWUS036ACH preferred)
-   Monitor mode + packet injection support
-   Detachable antenna

## Directional Antenna

-   2.4GHz or dual-band Yagi antenna
-   SMA connector compatible
-   Used for propagation testing and signal isolation

## GPS Module

-   u-blox 7/8 USB GPS (recommended)
-   GlobalSat BU-353-S4
-   VK-172 (budget option)

## Power

-   USB-C PD Power Bank (65W output recommended)
-   20,000--25,000mAh minimum

## Case

-   Pelican 1200 (recommended)
-   Apache 2800 (budget alternative)

------------------------------------------------------------------------

# Operating System Setup

Install Kali Linux (bare metal, XFCE desktop).

Post-install baseline:

``` bash
sudo apt update
sudo apt install aircrack-ng kismet wireshark tshark gpsd gpsd-clients tmux htop neovim git jq python3 python3-pip
sudo ufw --force enable
sudo systemctl disable bluetooth
```

------------------------------------------------------------------------

# Wireless Configuration

Identify interfaces:

``` bash
iwconfig
airmon-ng
```

Enable monitor mode:

``` bash
sudo airmon-ng start wlan1
```

Stop monitor mode:

``` bash
sudo airmon-ng stop wlan1mon
sudo systemctl restart NetworkManager
```

------------------------------------------------------------------------

# GPS Setup

Identify device:

``` bash
ls /dev/ttyUSB*
```

Start GPS daemon:

``` bash
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock
cgps
```

------------------------------------------------------------------------

# Field Workflow

## Phase 1: Passive Recon

-   Use omnidirectional antenna
-   Map SSIDs, channels, RSSI, encryption types

## Phase 2: Directed Testing

-   Switch to Yagi antenna
-   Measure RSSI delta and SNR
-   Record signal falloff

## Phase 3: Structured Logging

Create folder:

``` bash
mkdir -p ~/redops/{data,pcaps,kismet,reports,scripts,notes,wordlists,logs}
```

Store: - PCAP files - Kismet JSON exports - GPS logs - Markdown reports

------------------------------------------------------------------------

# Claude Utility Prompt Library

## Script Generator Template

Use when generating scripts:

You are my utility scripting assistant for a Kali Linux RedOps laptop.
Constraints: - Python 3.10+ - Standard libraries only unless approved -
Argparse, logging, and error handling required - Analyze local files
only

Output: 1) Short plan 2) Full script 3) Run instructions 4) Failure
modes

------------------------------------------------------------------------

## Report Generator Prompt

Generate a professional wireless survey report in Markdown from: -
Channel summary - Device summary - Field notes

Include: - Scope/Authorization - Environment - Findings - Risks -
Optimization Recommendations - Appendix

------------------------------------------------------------------------

# Reporting Pipeline

1)  Capture session
2)  Export data
3)  Use Claude to generate parsing scripts
4)  Produce Markdown report
5)  Convert to PDF (optional):

``` bash
sudo apt install pandoc texlive-latex-base
pandoc report.md -o report.pdf
```

------------------------------------------------------------------------

# Legal Guardrails

Allowed: - Your own networks - Lab APs - Written authorized audits

Never: - Target neighbors - Attempt unauthorized access - Capture
private data

------------------------------------------------------------------------

# System Identity

Suggested Names: - RedOps-Node-01 - Gorgon Edge RF

Role: Portable wireless assessment appliance with AI-assisted
automation.

------------------------------------------------------------------------

End of Artifact
