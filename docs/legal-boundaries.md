# Legal Boundaries for RedOPS Active Chain

> **WARNING**: The Active Chain (`modules/active/`) contains offensive security
capabilities including wireless deauthentication, evil-twin access points, ARP
scanning, port scanning, and autonomous vulnerability chaining. These capabilities
can disrupt networks and may violate local laws if used without authorization.

## Authorized Use Definition

RedOPS Active Chain modules **may only be used** under one of the following
conditions:

1. **Your own network or property** — You own the infrastructure being tested.
2. **Designated lab environment** — An isolated network explicitly provisioned
   for security research (e.g. a home lab with no production traffic, no guest
   access, and no upstream connectivity to third-party networks).
3. **Explicit written permission** — You hold a signed scope agreement,
   statement of work, or formal authorization letter from the owner or authorized
   representative of the target network.

Using RedOPS Active Chain capabilities on any network that does not meet one of
the three conditions above is **unauthorized use** and is **strictly prohibited**.

## What RedOPS Will Do (Active Chain)

When authorized and executed, the Active Chain can:

- Passively scan for nearby wireless access points and connected clients.
- Clone a legitimate access point (evil twin) to attract client connections.
- Send 802.11 deauthentication frames to disconnect clients from a legitimate AP.
- Perform ARP scanning on a local subnet to discover live hosts.
- Run nmap service and version scans against discovered hosts.
- Cross-reference discovered services against known CVEs.
- Orchestrate an autonomous ReAct agent that chains the above steps.

## What RedOPS Will NOT Do

RedOPS Active Chain **will never**:

- Attack, scan, or interfere with networks outside the explicitly authorized target.
- Exfiltrate data from captured clients to cloud services (egress is blocked to
  non-local endpoints during active execution).
- Operate without recorded operator consent (every active module refuses execution
  without a valid `ActiveAuthorization`).
- Run on non-root accounts where root privileges are required for the operation.
- Mask its activity or evade detection — all actions are logged to the audit trail.

## Jurisdiction

Laws governing wireless interception, network disruption, and unauthorized access
vary by jurisdiction. The following are examples and not legal advice:

- **United States**: 18 U.S.C. § 1030 (Computer Fraud and Abuse Act) and
  47 U.S.C. § 605 (Wiretap Act) may apply to unauthorized network access and
  interception of communications. Deauthentication attacks may be prosecuted
  as denial-of-service or interference with communications.
- **European Union**: Directive 2013/40/EU (Attacks against Information Systems)
  and national implementations criminalize unauthorized access and interference.
- **United Kingdom**: Computer Misuse Act 1990 sections 1–3 criminalize
  unauthorized access, unauthorized acts with intent, and unauthorized acts
  causing damage.

**You are responsible** for understanding and complying with the laws in your
jurisdiction. The RedOPS maintainers provide this tool for authorized security
professionals and researchers; we do not condone illegal use.

## Will / Won't Do List

| Capability | Will Do (Authorized) | Won't Do (Prohibited) |
|---|---|---|
| Deauth flood | On your own AP or lab AP with consent | Coffee shop, airport, neighbor's AP, corporate AP without SOW |
| Evil twin | Your own SSID or isolated lab SSID | Clone a third-party AP to harvest credentials |
| ARP scan | Your own subnet or lab subnet | Scan a corporate subnet you do not own |
| Port scan | Authorized target with written permission | Internet-wide scanning or scanning without scope |
| CVE check | As part of an authorized assessment | Weaponizing findings against unauthorized targets |
| Autonomous agent | Within authorized lab with operator monitoring | Unattended execution on production networks |

## Enforcement

The codebase enforces these boundaries through technical controls:

1. **Authorization gate** — Every `modules/active/` function calls
   `assert_active_authorized(ctx)`, which raises `ActiveAuthorizationError`
   if no recorded operator consent exists.
2. **Scope guard** — Existing `modules/compliance/scope_guard.py` validates
   that targets match allowed domains, IPs, BSSIDs, and subnets.
3. **Egress blocking** — `block_external_egress()` prevents cloud API calls
   during active chain execution, ensuring local-only operation.
4. **Audit logging** — Every authorization recording, module execution, and
   tool invocation is logged with timestamp, operator, and target.

## Reporting Misuse

If you discover RedOPS being used without authorization, or if you find a
vulnerability in the authorization/egress enforcement mechanisms, please report
it responsibly. See `SECURITY.md` for contact details.
