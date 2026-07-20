# Misuse Threat Model — RedOPS Active Chain

**Version**: 1.0.0  
**Date**: 2026-07-20  
**Scope**: Casual misuse of RedOPS `modules/active/` by unauthorized operators

## Threat Actor Profile

| Attribute | Description |
|---|---|
| **Actor** | Casual user with limited cybersecurity knowledge |
| **Motivation** | Curiosity, prank, or vague "testing" intent |
| **Skill** | Can clone a GitHub repo and run `pip install` |
| **Access** | Personal laptop, home internet, possibly a USB Wi-Fi adapter |
| **Risk** | Medium — not sophisticated, but the tool automates actions that
are illegal when unauthorized |

## Threat Scenarios

### Scenario 1: Coffee Shop Deauth

**Narrative**: User downloads RedOPS, runs the active chain in a coffee shop to
"see what happens," and deauthenticates patrons from the shop's Wi-Fi.

**Controls**:
- Root privileges required to put interface in monitor mode and send raw frames.
- `assert_active_authorized()` requires explicit operator consent + target assertion.
- Egress blocking prevents data exfiltration to cloud APIs.
- Audit logs record operator identity and timestamp.

**Residual Risk**: Determined user can fabricate authorization and run as root.
Mitigated by requiring explicit consent text and target assertion, which creates
psychological friction and legal accountability.

### Scenario 2: Neighbor Network Scan

**Narrative**: User points ARP scan and port scan at a neighbor's home network
discovered via wardriving.

**Controls**:
- `scope_guard.is_subnet_in_scope()` rejects subnets not in the allowed list.
- Strict mode defaults to `True`, so out-of-scope targets are blocked.
- Active authorization requires target assertion, forcing the operator to name
  the exact subnet they claim to own.

**Residual Risk**: User can add neighbor's subnet to scope config. Mitigated by
making scope config editable only via file (not CLI flag) and logging changes.

### Scenario 3: Autonomous Agent Runaway

**Narrative**: User starts the ReAct agent on a university network and it
chains from the lab subnet to the campus-wide VLAN.

**Controls**:
- `block_external_egress()` blocks cloud API calls, keeping the agent local-only.
- Scope guard checks every tool invocation's target against allowed subnets.
- Agent logs every thought/action/observation for post-hoc review.
- Maximum iteration limit (default 10) prevents infinite runaway.

**Residual Risk**: Agent could pivot within the allowed scope to sensitive systems.
Mitigated by requiring narrow scope assertions and operator monitoring.

## Technical Control Summary

| Control | Implementation | Effectiveness |
|---|---|---|
| **Authorization gate** | `assert_active_authorized(ctx)` in every active module | High — blocks accidental execution |
| **Scope guard** | `modules/compliance/scope_guard.py` | High — prevents out-of-scope targeting |
| **Egress blocking** | `modules/active/egress.py` thread-local patches | High — prevents cloud exfiltration |
| **Root requirement** | Subprocess `sudo` calls in wireless/network modules | Medium — OS-level deterrent |
| **Audit logging** | JSONL audit trail with operator + timestamp | Medium — accountability after the fact |
| **Consent text** | Explicit acknowledgment required | Medium — psychological friction |

## What This Threat Model Does NOT Cover

- **Insider threat**: A malicious authorized operator with valid credentials.
  This requires organizational controls (background checks, dual-control) outside
  the scope of the codebase.
- **Supply-chain attack**: Compromised dependency injecting malicious active
  modules. This requires dependency pinning and SBOM tracking.
- **Physical security**: Theft of the laptop running RedOPS. This requires
  full-disk encryption and screen locks.

## Recommendations for Operators

1. Run RedOPS Active Chain **only** on air-gapped or physically isolated networks.
2. Document every authorization in a signed scope agreement stored separately
   from the tool.
3. Review audit logs after every session.
4. Report any bypass of authorization/egress controls as a security vulnerability.
