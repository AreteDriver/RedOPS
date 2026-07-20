# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x | Yes |
| < 1.5 | No |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Use GitHub **Private Vulnerability Reporting** (enabled on this repository)
   or email **security@redops.dev** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgment within 48 hours
4. A fix will be prioritized based on severity

## Security Measures

This project uses:
- **CodeQL** — static analysis on every push
- **gitleaks** — secret scanning on every push
- **pip-audit** — dependency vulnerability scanning
- **Dependabot** — automated dependency updates

## Important Note

RedOPS is an offensive security tool intended for **authorized security testing only**. The tool itself is designed to find vulnerabilities in target systems — security reports should focus on vulnerabilities in RedOPS's own code, not in its intended functionality.

## Active Chain Authorization Requirements

The **Active Chain** (`modules/active/`) — wireless deauthentication, evil-twin
access points, ARP scanning, port scanning, and autonomous vulnerability chaining
— is **gated** by the following requirements:

1. **Recorded operator consent** is mandatory. Every active module calls
   `assert_active_authorized(ctx)`, which raises `ActiveAuthorizationError`
   if no valid authorization exists.
2. **Explicit target assertion** is required. The operator must name the exact
   target(s) they claim to own or have permission to test.
3. **Egress blocking** is enforced. `block_external_egress()` prevents cloud API
   calls during active chain execution, ensuring local-only operation.
4. **Legal review** is required before any release containing active modules.
   See `docs/legal-boundaries.md` for jurisdiction analysis and authorized-use
   definition.
5. **Operator runbook** must be followed. See `docs/operator-runbook.md` for
   step-by-step authorized engagement procedures.

Vulnerabilities in the authorization or egress enforcement mechanisms are
**critical** and in scope for this security policy.

## Scope

The following are in scope for security reports:
- Code injection in RedOPS itself
- Credential exposure or mishandling
- Authentication bypasses in the web interface
- Dependency vulnerabilities with known exploits
- Bypass of `assert_active_authorized()` or `block_external_egress()`
- Injection or mutation of audit log entries

Out of scope:
- Functionality that is working as designed (scanning, recon, etc.)
- Denial of service against the target (by design for active modules)
- Social engineering
