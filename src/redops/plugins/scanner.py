"""
Scanner Plugin Base Classes.

Provides base classes for building security scanner plugins.
"""

from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterator
from uuid import uuid4

from redops.core.plugin_system import BasePlugin, PluginMetadata, PluginType


class Severity(Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanPhase(Enum):
    """Scanner execution phases."""

    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class ScannerCapability(Enum):
    """Scanner capabilities."""

    NETWORK_SCAN = "network_scan"
    WEB_SCAN = "web_scan"
    API_SCAN = "api_scan"
    CODE_SCAN = "code_scan"
    CONTAINER_SCAN = "container_scan"
    CLOUD_SCAN = "cloud_scan"
    CREDENTIAL_SCAN = "credential_scan"
    CONFIGURATION_AUDIT = "configuration_audit"
    COMPLIANCE_CHECK = "compliance_check"


@dataclass
class Finding:
    """Security finding from a scan."""

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 1.0  # 0.0 to 1.0
    category: str = ""
    cwe_id: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None

    # Location
    target: str = ""
    location: str = ""
    line_number: int | None = None

    # Evidence
    evidence: str = ""
    request: str | None = None
    response: str | None = None

    # Remediation
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Metadata
    scanner: str = ""
    phase: ScanPhase = ScanPhase.VULNERABILITY
    timestamp: datetime = field(default_factory=datetime.now)
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "target": self.target,
            "location": self.location,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "remediation": self.remediation,
            "references": self.references,
            "scanner": self.scanner,
            "phase": self.phase.value,
            "timestamp": self.timestamp.isoformat(),
            "tags": list(self.tags),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create from dictionary."""
        return cls(
            id=data.get("id", str(uuid4())),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=Severity(data.get("severity", "info")),
            confidence=data.get("confidence", 1.0),
            category=data.get("category", ""),
            cwe_id=data.get("cwe_id"),
            cve_id=data.get("cve_id"),
            cvss_score=data.get("cvss_score"),
            target=data.get("target", ""),
            location=data.get("location", ""),
            line_number=data.get("line_number"),
            evidence=data.get("evidence", ""),
            request=data.get("request"),
            response=data.get("response"),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            scanner=data.get("scanner", ""),
            phase=ScanPhase(data.get("phase", "vulnerability")),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.now(),
            tags=set(data.get("tags", [])),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScannerResult:
    """Result of a scanner execution."""

    scanner_name: str
    target: str
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    success: bool = True
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        """Get scan duration."""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def finding_counts(self) -> dict[str, int]:
        """Get finding counts by severity."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "finding_counts": self.finding_counts,
            "stats": self.stats,
            "metadata": self.metadata,
        }


@dataclass
class ScannerConfig:
    """Configuration for a scanner."""

    timeout: float = 300.0  # seconds
    max_concurrent: int = 10
    retry_count: int = 3
    retry_delay: float = 1.0
    user_agent: str = "RedOPS Scanner/1.0"
    proxy: str | None = None
    verify_ssl: bool = True
    auth: dict[str, str] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    custom: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timeout": self.timeout,
            "max_concurrent": self.max_concurrent,
            "retry_count": self.retry_count,
            "retry_delay": self.retry_delay,
            "user_agent": self.user_agent,
            "proxy": self.proxy,
            "verify_ssl": self.verify_ssl,
            "auth": self.auth,
            "headers": self.headers,
            "custom": self.custom,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScannerConfig":
        """Create from dictionary."""
        return cls(
            timeout=data.get("timeout", 300.0),
            max_concurrent=data.get("max_concurrent", 10),
            retry_count=data.get("retry_count", 3),
            retry_delay=data.get("retry_delay", 1.0),
            user_agent=data.get("user_agent", "RedOPS Scanner/1.0"),
            proxy=data.get("proxy"),
            verify_ssl=data.get("verify_ssl", True),
            auth=data.get("auth"),
            headers=data.get("headers", {}),
            custom=data.get("custom", {}),
        )


class ScannerPlugin(BasePlugin):
    """
    Base class for scanner plugins.

    Scanner plugins perform security assessments against targets.
    They should inherit from this class and implement the required methods.

    Example:
        class PortScannerPlugin(ScannerPlugin):
            @classmethod
            def get_name(cls) -> str:
                return "port_scanner"

            @classmethod
            def get_capabilities(cls) -> Set[ScannerCapability]:
                return {ScannerCapability.NETWORK_SCAN}

            def scan(self, target: str, config: ScannerConfig) -> ScannerResult:
                # Perform port scanning
                ...
    """

    def __init__(self):
        """Initialize the scanner plugin."""
        self._hooks: dict[str, list[Callable]] = {
            "before_scan": [],
            "after_scan": [],
            "on_finding": [],
            "on_error": [],
        }

    @classmethod
    @abstractmethod
    def get_name(cls) -> str:
        """Get scanner name."""
        pass

    @classmethod
    @abstractmethod
    def get_version(cls) -> str:
        """Get scanner version."""
        pass

    @classmethod
    @abstractmethod
    def get_description(cls) -> str:
        """Get scanner description."""
        pass

    @classmethod
    @abstractmethod
    def get_capabilities(cls) -> set[ScannerCapability]:
        """Get scanner capabilities."""
        pass

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Bridge to BasePlugin interface using scanner-specific methods."""
        return PluginMetadata(
            name=cls.get_name(),
            version=cls.get_version(),
            description=cls.get_description(),
            plugin_type=PluginType.MODULE,
        )

    @classmethod
    def get_phases(cls) -> list[ScanPhase]:
        """Get scan phases this scanner operates in."""
        return [ScanPhase.VULNERABILITY]

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        """Get JSON schema for custom configuration."""
        return {}

    def initialize(self, config: ScannerConfig | None = None) -> None:
        """
        Initialize the scanner with configuration.

        Args:
            config: Scanner configuration
        """
        self.config = config or ScannerConfig()

    def shutdown(self) -> None:
        """Clean up scanner resources."""
        pass

    @abstractmethod
    def scan(self, target: str, config: ScannerConfig | None = None) -> ScannerResult:
        """
        Perform a scan against the target.

        Args:
            target: Target to scan (URL, IP, hostname, etc.)
            config: Optional scan-specific configuration

        Returns:
            ScannerResult with findings
        """
        pass

    def validate_target(self, target: str) -> bool:
        """
        Validate if target is suitable for this scanner.

        Args:
            target: Target to validate

        Returns:
            True if target is valid
        """
        return True

    def scan_async(
        self,
        target: str,
        config: ScannerConfig | None = None,
    ) -> Iterator[Finding]:
        """
        Perform scan and yield findings as they're discovered.

        Args:
            target: Target to scan
            config: Optional configuration

        Yields:
            Finding objects as discovered
        """
        result = self.scan(target, config)
        yield from result.findings

    def add_hook(self, event: str, callback: Callable) -> None:
        """
        Add a hook callback.

        Args:
            event: Event name (before_scan, after_scan, on_finding, on_error)
            callback: Callback function
        """
        if event in self._hooks:
            self._hooks[event].append(callback)

    def remove_hook(self, event: str, callback: Callable) -> bool:
        """
        Remove a hook callback.

        Args:
            event: Event name
            callback: Callback to remove

        Returns:
            True if removed
        """
        if event in self._hooks and callback in self._hooks[event]:
            self._hooks[event].remove(callback)
            return True
        return False

    def _trigger_hook(self, event: str, *args, **kwargs) -> None:
        """Trigger hook callbacks."""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args, **kwargs)
            except (RuntimeError, TypeError, ValueError, OSError):
                pass  # Ignore hook errors

    def _create_finding(
        self,
        title: str,
        severity: Severity,
        target: str,
        **kwargs,
    ) -> Finding:
        """
        Helper to create a finding with scanner metadata.

        Args:
            title: Finding title
            severity: Severity level
            target: Target where found
            **kwargs: Additional finding fields

        Returns:
            Finding object
        """
        finding = Finding(
            title=title,
            severity=severity,
            target=target,
            scanner=self.get_name(),
            **kwargs,
        )
        self._trigger_hook("on_finding", finding)
        return finding

    def _create_result(
        self,
        target: str,
        findings: list[Finding] | None = None,
        **kwargs,
    ) -> ScannerResult:
        """
        Helper to create a scanner result.

        Args:
            target: Scan target
            findings: List of findings
            **kwargs: Additional result fields

        Returns:
            ScannerResult object
        """
        return ScannerResult(
            scanner_name=self.get_name(),
            target=target,
            findings=findings or [],
            **kwargs,
        )


class CompositeScanner:
    """
    Combines multiple scanners into a single scan.

    Example:
        composite = CompositeScanner()
        composite.add_scanner(PortScanner())
        composite.add_scanner(WebScanner())

        result = composite.scan("https://example.com")
    """

    def __init__(self):
        """Initialize composite scanner."""
        self._scanners: list[ScannerPlugin] = []

    def add_scanner(self, scanner: ScannerPlugin) -> None:
        """Add a scanner to the composite."""
        self._scanners.append(scanner)

    def remove_scanner(self, scanner: ScannerPlugin) -> bool:
        """Remove a scanner from the composite."""
        if scanner in self._scanners:
            self._scanners.remove(scanner)
            return True
        return False

    def scan(
        self,
        target: str,
        config: ScannerConfig | None = None,
        parallel: bool = False,
    ) -> list[ScannerResult]:
        """
        Run all scanners against target.

        Args:
            target: Target to scan
            config: Shared configuration
            parallel: Run scanners in parallel

        Returns:
            List of results from each scanner
        """
        results = []

        if parallel:
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {
                    executor.submit(s.scan, target, config): s
                    for s in self._scanners
                    if s.validate_target(target)
                }
                for future in concurrent.futures.as_completed(futures):
                    try:
                        results.append(future.result())
                    except (RuntimeError, ImportError, TypeError, ValueError, OSError, ConnectionError) as e:
                        scanner = futures[future]
                        results.append(
                            ScannerResult(
                                scanner_name=scanner.get_name(),
                                target=target,
                                success=False,
                                error=str(e),
                            )
                        )
        else:
            for scanner in self._scanners:
                if scanner.validate_target(target):
                    try:
                        results.append(scanner.scan(target, config))
                    except (RuntimeError, ImportError, TypeError, ValueError, OSError, ConnectionError) as e:
                        results.append(
                            ScannerResult(
                                scanner_name=scanner.get_name(),
                                target=target,
                                success=False,
                                error=str(e),
                            )
                        )

        return results

    def get_all_findings(self, results: list[ScannerResult]) -> list[Finding]:
        """Get all findings from multiple results."""
        findings = []
        for result in results:
            findings.extend(result.findings)
        return findings

    @property
    def scanners(self) -> list[ScannerPlugin]:
        """Get list of scanners."""
        return self._scanners.copy()

    @property
    def capabilities(self) -> set[ScannerCapability]:
        """Get combined capabilities."""
        caps = set()
        for scanner in self._scanners:
            caps.update(scanner.get_capabilities())
        return caps
