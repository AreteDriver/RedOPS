"""
Example HTTP Header Scanner Plugin.

Demonstrates building a web scanner plugin.
"""

from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from redops.plugins.scanner import (
    Finding,
    ScannerCapability,
    ScannerConfig,
    ScannerPlugin,
    ScannerResult,
    ScanPhase,
    Severity,
)


class HeaderScannerPlugin(ScannerPlugin):
    """
    HTTP security header scanner plugin.

    Checks for missing or misconfigured security headers.
    """

    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": Severity.HIGH,
            "description": "HSTS header forces secure connections",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
            "cwe_id": "CWE-319",
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "CSP prevents XSS and injection attacks",
            "remediation": "Implement a Content-Security-Policy header",
            "cwe_id": "CWE-79",
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "Prevents MIME-type sniffing",
            "remediation": "Add 'X-Content-Type-Options: nosniff'",
            "cwe_id": "CWE-16",
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "Prevents clickjacking attacks",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
            "cwe_id": "CWE-1021",
        },
        "X-XSS-Protection": {
            "severity": Severity.LOW,
            "description": "Legacy XSS protection (deprecated but still useful)",
            "remediation": "Add 'X-XSS-Protection: 1; mode=block'",
            "cwe_id": "CWE-79",
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Controls referrer information sent with requests",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
            "cwe_id": "CWE-200",
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "description": "Controls browser features and APIs",
            "remediation": "Add 'Permissions-Policy' to restrict browser features",
            "cwe_id": "CWE-16",
        },
    }

    # Headers that should not be present
    BAD_HEADERS = {
        "Server": {
            "severity": Severity.INFO,
            "description": "Server header reveals server software",
            "remediation": "Remove or obfuscate the Server header",
        },
        "X-Powered-By": {
            "severity": Severity.INFO,
            "description": "X-Powered-By reveals technology stack",
            "remediation": "Remove the X-Powered-By header",
        },
        "X-AspNet-Version": {
            "severity": Severity.LOW,
            "description": "Reveals ASP.NET version",
            "remediation": "Disable X-AspNet-Version in web.config",
        },
    }

    @classmethod
    def get_name(cls) -> str:
        return "header-scanner"

    @classmethod
    def get_version(cls) -> str:
        return "1.0.0"

    @classmethod
    def get_description(cls) -> str:
        return "HTTP security header scanner"

    @classmethod
    def get_capabilities(cls) -> Set[ScannerCapability]:
        return {ScannerCapability.WEB_SCAN}

    @classmethod
    def get_phases(cls) -> List[ScanPhase]:
        return [ScanPhase.VULNERABILITY]

    def validate_target(self, target: str) -> bool:
        """Validate target is a URL."""
        try:
            parsed = urlparse(target)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except Exception:
            return False

    def scan(
        self,
        target: str,
        config: Optional[ScannerConfig] = None,
    ) -> ScannerResult:
        """
        Scan target for security header issues.

        Args:
            target: URL to scan
            config: Scanner configuration

        Returns:
            ScannerResult with findings
        """
        config = config or self.config
        self._trigger_hook("before_scan", target, config)

        result = self._create_result(target)

        try:
            # Fetch headers
            headers = self._fetch_headers(target, config)

            # Check for missing security headers
            for header_name, header_info in self.SECURITY_HEADERS.items():
                if header_name.lower() not in {h.lower() for h in headers}:
                    finding = self._create_finding(
                        title=f"Missing Security Header: {header_name}",
                        severity=header_info["severity"],
                        target=target,
                        description=header_info["description"],
                        category="web-security",
                        cwe_id=header_info.get("cwe_id"),
                        remediation=header_info["remediation"],
                        metadata={"header": header_name},
                    )
                    result.findings.append(finding)

            # Check for headers that reveal information
            for header_name, header_info in self.BAD_HEADERS.items():
                for resp_header, value in headers.items():
                    if resp_header.lower() == header_name.lower():
                        finding = self._create_finding(
                            title=f"Information Disclosure: {header_name}",
                            severity=header_info["severity"],
                            target=target,
                            description=f"{header_info['description']}: {value}",
                            category="information-disclosure",
                            remediation=header_info["remediation"],
                            evidence=f"{header_name}: {value}",
                            metadata={"header": header_name, "value": value},
                        )
                        result.findings.append(finding)

            # Check CSP if present
            csp = self._get_header(headers, "Content-Security-Policy")
            if csp:
                csp_findings = self._analyze_csp(target, csp)
                result.findings.extend(csp_findings)

            # Check HSTS if present
            hsts = self._get_header(headers, "Strict-Transport-Security")
            if hsts:
                hsts_findings = self._analyze_hsts(target, hsts)
                result.findings.extend(hsts_findings)

            result.stats = {
                "headers_checked": len(self.SECURITY_HEADERS) + len(self.BAD_HEADERS),
                "headers_found": len(headers),
                "issues_found": len(result.findings),
            }

            # Store response headers
            result.metadata["response_headers"] = headers

        except Exception as e:
            result.success = False
            result.error = str(e)
            self._trigger_hook("on_error", e)

        result.completed_at = datetime.now()
        self._trigger_hook("after_scan", result)

        return result

    def _fetch_headers(
        self,
        url: str,
        config: ScannerConfig,
    ) -> Dict[str, str]:
        """Fetch HTTP headers from URL."""
        import urllib.request

        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": config.user_agent,
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=config.timeout) as response:
                return dict(response.headers)
        except urllib.error.HTTPError as e:
            # Still return headers from error response
            return dict(e.headers) if hasattr(e, "headers") else {}

    def _get_header(self, headers: Dict[str, str], name: str) -> Optional[str]:
        """Get header value case-insensitively."""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def _analyze_csp(self, target: str, csp: str) -> List[Finding]:
        """Analyze Content-Security-Policy for issues."""
        findings = []

        # Check for unsafe directives
        if "unsafe-inline" in csp:
            findings.append(
                self._create_finding(
                    title="CSP allows unsafe-inline",
                    severity=Severity.MEDIUM,
                    target=target,
                    description="CSP policy allows inline scripts/styles which weakens XSS protection",
                    category="web-security",
                    cwe_id="CWE-79",
                    remediation="Remove 'unsafe-inline' and use nonces or hashes instead",
                    evidence=f"CSP: {csp}",
                )
            )

        if "unsafe-eval" in csp:
            findings.append(
                self._create_finding(
                    title="CSP allows unsafe-eval",
                    severity=Severity.MEDIUM,
                    target=target,
                    description="CSP policy allows eval() which can be exploited for code execution",
                    category="web-security",
                    cwe_id="CWE-95",
                    remediation="Remove 'unsafe-eval' from CSP",
                    evidence=f"CSP: {csp}",
                )
            )

        # Check for wildcard sources
        if "*" in csp and "script-src" in csp:
            findings.append(
                self._create_finding(
                    title="CSP has wildcard script source",
                    severity=Severity.HIGH,
                    target=target,
                    description="CSP allows scripts from any origin",
                    category="web-security",
                    cwe_id="CWE-79",
                    remediation="Specify explicit script sources instead of wildcards",
                    evidence=f"CSP: {csp}",
                )
            )

        return findings

    def _analyze_hsts(self, target: str, hsts: str) -> List[Finding]:
        """Analyze Strict-Transport-Security for issues."""
        findings = []

        # Check max-age
        if "max-age=" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:  # Less than 1 year
                    findings.append(
                        self._create_finding(
                            title="HSTS max-age too short",
                            severity=Severity.LOW,
                            target=target,
                            description=f"HSTS max-age is {max_age} seconds, recommend at least 31536000 (1 year)",
                            category="web-security",
                            cwe_id="CWE-319",
                            remediation="Increase HSTS max-age to at least 31536000",
                            evidence=f"HSTS: {hsts}",
                        )
                    )
            except (ValueError, IndexError):
                pass

        # Check for includeSubDomains
        if "includeSubDomains" not in hsts.lower():
            findings.append(
                self._create_finding(
                    title="HSTS missing includeSubDomains",
                    severity=Severity.INFO,
                    target=target,
                    description="HSTS should include subdomains for complete protection",
                    category="web-security",
                    cwe_id="CWE-319",
                    remediation="Add 'includeSubDomains' to HSTS header",
                    evidence=f"HSTS: {hsts}",
                )
            )

        return findings
