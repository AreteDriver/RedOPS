# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x | Yes |
| < 1.5 | No |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email **jamesyng79@gmail.com** with:
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

## Scope

The following are in scope for security reports:
- Code injection in RedOPS itself
- Credential exposure or mishandling
- Authentication bypasses in the web interface
- Dependency vulnerabilities with known exploits

Out of scope:
- Functionality that is working as designed (scanning, recon, etc.)
- Denial of service
- Social engineering
