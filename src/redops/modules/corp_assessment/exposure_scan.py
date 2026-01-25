"""
Corporate exposure scanning module.

High-level exposure assessment for corporate entities.
Analyzes public-facing assets, exposed services, and information leakage.

IMPORTANT: This module operates on PUBLIC information only.
Pattern-based analysis without active scanning.
"""

from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
from redops.core.context import Context
from redops.core.models import Finding


class ExposureSeverity(Enum):
    """Severity levels for exposure findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExposureCategory(Enum):
    """Categories of exposure."""

    SOURCE_CODE = "source_code"
    CONFIGURATION = "configuration"
    CREDENTIALS = "credentials"
    BACKUP = "backup"
    DEBUG = "debug"
    CLOUD_STORAGE = "cloud_storage"
    API = "api"
    DATABASE = "database"
    ADMIN = "admin"
    DOCUMENTATION = "documentation"
    INFRASTRUCTURE = "infrastructure"


@dataclass
class ExposurePattern:
    """Pattern for detecting exposed resources."""

    name: str
    pattern: str  # Regex pattern
    category: ExposureCategory
    severity: ExposureSeverity
    description: str
    remediation: str
    indicators: List[str] = field(default_factory=list)

    def matches(self, text: str) -> bool:
        """Check if pattern matches text."""
        return bool(re.search(self.pattern, text, re.IGNORECASE))


@dataclass
class ExposureFinding:
    """Represents an exposure finding."""

    title: str
    category: ExposureCategory
    severity: ExposureSeverity
    description: str
    evidence: List[str]
    remediation: str
    affected_assets: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "affected_assets": self.affected_assets,
            "metadata": self.metadata,
        }

    def to_finding(self) -> Finding:
        """Convert to Finding model."""
        return Finding(
            module="exposure_scan",
            title=self.title,
            description=self.description,
            severity=self.severity.value,
            data={
                "category": self.category.value,
                "evidence": self.evidence,
                "remediation": self.remediation,
                "affected_assets": self.affected_assets,
            },
        )


# ============================================================================
# Exposure Pattern Definitions
# ============================================================================

# Source Code Exposure Patterns
SOURCE_CODE_PATTERNS = [
    ExposurePattern(
        name="Git Repository Exposed",
        pattern=r"\.git(/|$)|/\.git/",
        category=ExposureCategory.SOURCE_CODE,
        severity=ExposureSeverity.CRITICAL,
        description="Git repository directory exposed, potentially revealing source code and history",
        remediation="Block access to .git directory in web server configuration",
        indicators=[".git/HEAD", ".git/config", ".git/objects"],
    ),
    ExposurePattern(
        name="SVN Repository Exposed",
        pattern=r"\.svn(/|$)|/\.svn/",
        category=ExposureCategory.SOURCE_CODE,
        severity=ExposureSeverity.HIGH,
        description="SVN repository directory exposed",
        remediation="Block access to .svn directory",
        indicators=[".svn/entries", ".svn/wc.db"],
    ),
    ExposurePattern(
        name="Source Map Files",
        pattern=r"\.map$|\.js\.map$|\.css\.map$",
        category=ExposureCategory.SOURCE_CODE,
        severity=ExposureSeverity.MEDIUM,
        description="JavaScript/CSS source maps exposed, revealing original source code",
        remediation="Remove source map files from production or restrict access",
    ),
    ExposurePattern(
        name="IDE Configuration",
        pattern=r"\.idea(/|$)|\.vscode(/|$)|\.eclipse(/|$)",
        category=ExposureCategory.SOURCE_CODE,
        severity=ExposureSeverity.LOW,
        description="IDE configuration directories exposed",
        remediation="Remove IDE configuration from web-accessible directories",
    ),
]

# Configuration Exposure Patterns
CONFIG_PATTERNS = [
    ExposurePattern(
        name="Environment File Exposed",
        pattern=r"\.env($|\.local|\.prod|\.dev|\.staging|\.example)",
        category=ExposureCategory.CONFIGURATION,
        severity=ExposureSeverity.CRITICAL,
        description="Environment configuration file exposed, may contain credentials",
        remediation="Remove .env files from public access, use server-side environment variables",
    ),
    ExposurePattern(
        name="Configuration File Exposed",
        pattern=r"config\.(json|yml|yaml|xml|ini|php|py)$",
        category=ExposureCategory.CONFIGURATION,
        severity=ExposureSeverity.HIGH,
        description="Application configuration file exposed",
        remediation="Move configuration files outside web root or restrict access",
    ),
    ExposurePattern(
        name="Docker Configuration",
        pattern=r"docker-compose\.(yml|yaml)|Dockerfile|\.dockerignore",
        category=ExposureCategory.CONFIGURATION,
        severity=ExposureSeverity.MEDIUM,
        description="Docker configuration files exposed",
        remediation="Remove Docker configuration from public directories",
    ),
    ExposurePattern(
        name="Kubernetes Configuration",
        pattern=r"\.kube/|kubeconfig|k8s.*\.(yml|yaml)",
        category=ExposureCategory.CONFIGURATION,
        severity=ExposureSeverity.HIGH,
        description="Kubernetes configuration exposed",
        remediation="Secure Kubernetes configuration files",
    ),
    ExposurePattern(
        name="Web Server Configuration",
        pattern=r"\.htaccess|nginx\.conf|apache.*\.conf|web\.config",
        category=ExposureCategory.CONFIGURATION,
        severity=ExposureSeverity.MEDIUM,
        description="Web server configuration file exposed",
        remediation="Restrict access to server configuration files",
    ),
]

# Credential Exposure Patterns
CREDENTIAL_PATTERNS = [
    ExposurePattern(
        name="Private Key Exposed",
        pattern=r"\.(pem|key|p12|pfx|ppk)$|id_rsa|id_ed25519",
        category=ExposureCategory.CREDENTIALS,
        severity=ExposureSeverity.CRITICAL,
        description="Private key file exposed",
        remediation="Immediately rotate affected keys and remove from public access",
    ),
    ExposurePattern(
        name="AWS Credentials",
        pattern=r"aws_access_key|aws_secret|AKIA[0-9A-Z]{16}",
        category=ExposureCategory.CREDENTIALS,
        severity=ExposureSeverity.CRITICAL,
        description="AWS credentials or access keys exposed",
        remediation="Rotate AWS credentials immediately",
    ),
    ExposurePattern(
        name="API Keys in URL",
        pattern=r"api[_-]?key=|apikey=|access[_-]?token=|auth[_-]?token=",
        category=ExposureCategory.CREDENTIALS,
        severity=ExposureSeverity.HIGH,
        description="API keys or tokens exposed in URLs",
        remediation="Remove API keys from URLs, use secure header-based authentication",
    ),
    ExposurePattern(
        name="Password in Configuration",
        pattern=r"password\s*[=:]\s*['\"]?[^'\"\s]+|passwd\s*[=:]",
        category=ExposureCategory.CREDENTIALS,
        severity=ExposureSeverity.CRITICAL,
        description="Password found in configuration",
        remediation="Use environment variables or secrets management for passwords",
    ),
    ExposurePattern(
        name="Database Connection String",
        pattern=r"(mysql|postgres|mongodb|redis)://[^@]+@|jdbc:",
        category=ExposureCategory.CREDENTIALS,
        severity=ExposureSeverity.CRITICAL,
        description="Database connection string with credentials exposed",
        remediation="Use environment variables for database credentials",
    ),
]

# Backup File Patterns
BACKUP_PATTERNS = [
    ExposurePattern(
        name="Backup File Exposed",
        pattern=r"\.(bak|backup|old|orig|copy|tmp)$",
        category=ExposureCategory.BACKUP,
        severity=ExposureSeverity.HIGH,
        description="Backup file exposed, may contain sensitive data",
        remediation="Remove backup files from public directories",
    ),
    ExposurePattern(
        name="Database Dump",
        pattern=r"\.(sql|dump|db)$|database.*\.(sql|bak)",
        category=ExposureCategory.BACKUP,
        severity=ExposureSeverity.CRITICAL,
        description="Database dump file exposed",
        remediation="Remove database dumps from public access immediately",
    ),
    ExposurePattern(
        name="Archive Files",
        pattern=r"\.(zip|tar|tar\.gz|tgz|rar|7z)$",
        category=ExposureCategory.BACKUP,
        severity=ExposureSeverity.MEDIUM,
        description="Archive file exposed, may contain sensitive content",
        remediation="Review and remove unnecessary archive files",
    ),
    ExposurePattern(
        name="Editor Backup Files",
        pattern=r"~$|\.swp$|\.swo$|\#.*\#$",
        category=ExposureCategory.BACKUP,
        severity=ExposureSeverity.LOW,
        description="Editor backup/swap files exposed",
        remediation="Remove editor temporary files from public directories",
    ),
]

# Debug/Development Exposure Patterns
DEBUG_PATTERNS = [
    ExposurePattern(
        name="Debug Endpoint",
        pattern=r"/debug/|/phpinfo|/server-status|/server-info|/_profiler",
        category=ExposureCategory.DEBUG,
        severity=ExposureSeverity.HIGH,
        description="Debug endpoint exposed",
        remediation="Disable debug endpoints in production",
    ),
    ExposurePattern(
        name="Stack Trace Exposure",
        pattern=r"stack\s*trace|traceback|exception.*at\s+\w+\.\w+",
        category=ExposureCategory.DEBUG,
        severity=ExposureSeverity.MEDIUM,
        description="Stack traces exposed in responses",
        remediation="Implement proper error handling, hide stack traces in production",
    ),
    ExposurePattern(
        name="Development Console",
        pattern=r"/console|/shell|/terminal|/admin/console",
        category=ExposureCategory.DEBUG,
        severity=ExposureSeverity.CRITICAL,
        description="Development console exposed",
        remediation="Remove or secure development consoles",
    ),
    ExposurePattern(
        name="Log Files Exposed",
        pattern=r"\.(log|logs)$|/logs/|/var/log",
        category=ExposureCategory.DEBUG,
        severity=ExposureSeverity.HIGH,
        description="Log files exposed",
        remediation="Remove log files from public access",
    ),
]

# Cloud Storage Patterns
CLOUD_PATTERNS = [
    ExposurePattern(
        name="AWS S3 Bucket",
        pattern=r"s3\.amazonaws\.com|\.s3\.|s3://|s3-[a-z]+-\d+\.amazonaws",
        category=ExposureCategory.CLOUD_STORAGE,
        severity=ExposureSeverity.MEDIUM,
        description="AWS S3 bucket reference found",
        remediation="Verify S3 bucket permissions are properly configured",
        indicators=["ListBucket", "GetObject", "public-read"],
    ),
    ExposurePattern(
        name="Azure Blob Storage",
        pattern=r"\.blob\.core\.windows\.net|azure.*storage",
        category=ExposureCategory.CLOUD_STORAGE,
        severity=ExposureSeverity.MEDIUM,
        description="Azure Blob Storage reference found",
        remediation="Verify Azure storage access controls",
    ),
    ExposurePattern(
        name="Google Cloud Storage",
        pattern=r"storage\.googleapis\.com|storage\.cloud\.google|gs://",
        category=ExposureCategory.CLOUD_STORAGE,
        severity=ExposureSeverity.MEDIUM,
        description="Google Cloud Storage reference found",
        remediation="Verify GCS bucket permissions",
    ),
    ExposurePattern(
        name="Firebase Storage",
        pattern=r"firebasestorage\.googleapis\.com|\.firebaseio\.com",
        category=ExposureCategory.CLOUD_STORAGE,
        severity=ExposureSeverity.MEDIUM,
        description="Firebase storage reference found",
        remediation="Review Firebase security rules",
    ),
]

# API Exposure Patterns
API_PATTERNS = [
    ExposurePattern(
        name="GraphQL Endpoint",
        pattern=r"/graphql|/graphiql|/playground",
        category=ExposureCategory.API,
        severity=ExposureSeverity.MEDIUM,
        description="GraphQL endpoint exposed",
        remediation="Implement authentication and disable introspection in production",
    ),
    ExposurePattern(
        name="Swagger/OpenAPI Documentation",
        pattern=r"/swagger|/api-docs|/openapi\.json|/swagger\.json",
        category=ExposureCategory.API,
        severity=ExposureSeverity.LOW,
        description="API documentation exposed",
        remediation="Restrict API documentation access in production if sensitive",
    ),
    ExposurePattern(
        name="API Version Exposure",
        pattern=r"/api/v[0-9]+|/v[0-9]+/api",
        category=ExposureCategory.API,
        severity=ExposureSeverity.INFO,
        description="API versioning detected",
        remediation="Ensure deprecated API versions are properly secured",
    ),
]

# Admin/Management Patterns
ADMIN_PATTERNS = [
    ExposurePattern(
        name="Admin Panel",
        pattern=r"/admin|/administrator|/wp-admin|/manager|/backend",
        category=ExposureCategory.ADMIN,
        severity=ExposureSeverity.MEDIUM,
        description="Admin panel detected",
        remediation="Implement strong authentication, consider IP restriction",
    ),
    ExposurePattern(
        name="Database Admin",
        pattern=r"/phpmyadmin|/adminer|/pgadmin|/mongodb",
        category=ExposureCategory.ADMIN,
        severity=ExposureSeverity.HIGH,
        description="Database administration interface exposed",
        remediation="Remove or secure database admin interfaces",
    ),
    ExposurePattern(
        name="CMS Admin",
        pattern=r"/wp-login|/user/login|/admin/login|/cms|/drupal",
        category=ExposureCategory.ADMIN,
        severity=ExposureSeverity.MEDIUM,
        description="CMS login/admin detected",
        remediation="Implement brute force protection and strong authentication",
    ),
]

# Infrastructure Patterns
INFRASTRUCTURE_PATTERNS = [
    ExposurePattern(
        name="Internal IP Address",
        pattern=r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        category=ExposureCategory.INFRASTRUCTURE,
        severity=ExposureSeverity.LOW,
        description="Internal IP address exposed",
        remediation="Remove internal IP addresses from public-facing content",
    ),
    ExposurePattern(
        name="Internal Hostname",
        pattern=r"\.(internal|local|localhost|corp|lan)($|/|:)",
        category=ExposureCategory.INFRASTRUCTURE,
        severity=ExposureSeverity.LOW,
        description="Internal hostname reference found",
        remediation="Remove internal hostname references from public content",
    ),
    ExposurePattern(
        name="Server Version Disclosure",
        pattern=r"(Apache|nginx|IIS|Tomcat|Node|PHP)/[\d\.]+",
        category=ExposureCategory.INFRASTRUCTURE,
        severity=ExposureSeverity.LOW,
        description="Server version information exposed",
        remediation="Configure server to hide version information",
    ),
]

# Combine all patterns
ALL_PATTERNS = (
    SOURCE_CODE_PATTERNS
    + CONFIG_PATTERNS
    + CREDENTIAL_PATTERNS
    + BACKUP_PATTERNS
    + DEBUG_PATTERNS
    + CLOUD_PATTERNS
    + API_PATTERNS
    + ADMIN_PATTERNS
    + INFRASTRUCTURE_PATTERNS
)


# ============================================================================
# Sensitive File Definitions
# ============================================================================

SENSITIVE_FILES = {
    # Configuration files
    ".env": ("Environment variables", ExposureSeverity.CRITICAL),
    ".env.local": ("Local environment variables", ExposureSeverity.CRITICAL),
    ".env.production": ("Production environment variables", ExposureSeverity.CRITICAL),
    "config.php": ("PHP configuration", ExposureSeverity.HIGH),
    "config.json": ("JSON configuration", ExposureSeverity.HIGH),
    "settings.py": ("Python settings", ExposureSeverity.HIGH),
    "application.yml": ("Spring configuration", ExposureSeverity.HIGH),
    "database.yml": ("Database configuration", ExposureSeverity.HIGH),
    "secrets.yml": ("Secrets file", ExposureSeverity.CRITICAL),
    # Credential files
    ".htpasswd": ("Apache password file", ExposureSeverity.CRITICAL),
    ".netrc": ("FTP credentials", ExposureSeverity.CRITICAL),
    ".npmrc": ("NPM configuration", ExposureSeverity.HIGH),
    ".pypirc": ("PyPI credentials", ExposureSeverity.CRITICAL),
    "credentials.json": ("Credentials file", ExposureSeverity.CRITICAL),
    "service-account.json": ("Service account key", ExposureSeverity.CRITICAL),
    # Key files
    "id_rsa": ("SSH private key", ExposureSeverity.CRITICAL),
    "id_rsa.pub": ("SSH public key", ExposureSeverity.LOW),
    "id_ed25519": ("SSH private key", ExposureSeverity.CRITICAL),
    ".pem": ("PEM certificate/key", ExposureSeverity.HIGH),
    ".key": ("Private key", ExposureSeverity.CRITICAL),
    ".p12": ("PKCS12 certificate", ExposureSeverity.HIGH),
    # Backup files
    "backup.sql": ("Database backup", ExposureSeverity.CRITICAL),
    "dump.sql": ("Database dump", ExposureSeverity.CRITICAL),
    "database.sql": ("Database export", ExposureSeverity.CRITICAL),
    ".sql.gz": ("Compressed SQL backup", ExposureSeverity.CRITICAL),
    # Version control
    ".git/config": ("Git configuration", ExposureSeverity.HIGH),
    ".git/HEAD": ("Git HEAD reference", ExposureSeverity.HIGH),
    ".gitignore": ("Git ignore file", ExposureSeverity.LOW),
    ".svn/entries": ("SVN metadata", ExposureSeverity.HIGH),
    # Debug/Development
    "phpinfo.php": ("PHP info page", ExposureSeverity.MEDIUM),
    "info.php": ("PHP info page", ExposureSeverity.MEDIUM),
    "debug.log": ("Debug log", ExposureSeverity.HIGH),
    "error.log": ("Error log", ExposureSeverity.HIGH),
    "access.log": ("Access log", ExposureSeverity.MEDIUM),
}


# ============================================================================
# Common Exposed Paths
# ============================================================================

COMMON_EXPOSED_PATHS = [
    # Version control
    "/.git/",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/",
    "/.svn/entries",
    "/.hg/",
    # Configuration
    "/.env",
    "/config.php",
    "/config.json",
    "/settings.py",
    "/wp-config.php",
    "/web.config",
    # Backups
    "/backup/",
    "/backups/",
    "/db/",
    "/database/",
    "/dump.sql",
    "/backup.zip",
    # Debug
    "/debug/",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/server-status",
    "/server-info",
    # Admin
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/adminer.php",
    # API
    "/api/",
    "/graphql",
    "/swagger/",
    "/api-docs/",
    # Logs
    "/logs/",
    "/log/",
    "/error.log",
    "/access.log",
    "/debug.log",
    # Common sensitive
    "/robots.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]


# ============================================================================
# Main Functions
# ============================================================================


def scan_exposure(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Scan for corporate exposure.

    Analyzes context data for:
    - Exposed source code patterns
    - Configuration file exposure
    - Credential leakage
    - Cloud storage misconfigurations
    - Debug/development artifacts
    - Admin interface exposure

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - target: Override target
            - categories: List of ExposureCategory to check
            - min_severity: Minimum severity to report
            - include_paths: Whether to check common paths

    Returns:
        Updated context with exposure findings
    """
    params = params or {}
    target = params.get("target") or ctx.target

    if not target:
        ctx.log("No target specified for exposure scan", level="WARNING")
        return ctx

    ctx.log(f"Scanning exposure for: {target}", level="INFO")

    # Initialize results
    exposure_data = {
        "target": target,
        "findings": [],
        "public_assets": [],
        "exposed_paths": [],
        "sensitive_files": [],
        "cloud_references": [],
        "credential_exposures": [],
        "summary": {},
    }

    # Get categories to check
    categories = params.get("categories")
    if categories:
        categories = [
            ExposureCategory(c) if isinstance(c, str) else c for c in categories
        ]

    # Get minimum severity
    min_severity = params.get("min_severity", "info")
    min_severity_order = ["critical", "high", "medium", "low", "info"]
    min_severity_idx = min_severity_order.index(min_severity.lower())

    # Analyze context data for exposures
    all_findings = []

    # Check domain profile
    domain_profile = ctx.get("domain_profile", {})
    all_findings.extend(analyze_domain_exposure(domain_profile))

    # Check tech stack
    tech_stack = ctx.get("tech_stack", {})
    all_findings.extend(analyze_tech_stack_exposure(tech_stack))

    # Check code artifacts
    code_artifacts = ctx.get("code_artifacts", {})
    all_findings.extend(analyze_code_artifacts_exposure(code_artifacts))

    # Check document metadata
    doc_metadata = ctx.get("document_metadata", {})
    all_findings.extend(analyze_document_exposure(doc_metadata))

    # Check for exposed paths in context
    all_findings.extend(analyze_paths_in_context(ctx))

    # Check for cloud storage references
    cloud_refs = find_cloud_references(ctx)
    exposure_data["cloud_references"] = cloud_refs
    all_findings.extend(generate_cloud_findings(cloud_refs))

    # Check for credential patterns
    cred_exposures = find_credential_exposures(ctx)
    exposure_data["credential_exposures"] = cred_exposures
    all_findings.extend(generate_credential_findings(cred_exposures))

    # Identify public assets from context
    exposure_data["public_assets"] = identify_public_assets_from_context(ctx)

    # Get sensitive files detected
    exposure_data["sensitive_files"] = find_sensitive_files_in_context(ctx)

    # Filter by category if specified
    if categories:
        all_findings = [f for f in all_findings if f.category in categories]

    # Filter by severity
    filtered_findings = []
    for finding in all_findings:
        finding_severity_idx = min_severity_order.index(finding.severity.value)
        if finding_severity_idx <= min_severity_idx:
            filtered_findings.append(finding)

    # Deduplicate findings
    unique_findings = deduplicate_findings(filtered_findings)

    # Convert to dictionaries
    exposure_data["findings"] = [f.to_dict() for f in unique_findings]

    # Generate summary
    exposure_data["summary"] = generate_exposure_summary(unique_findings)

    # Add findings to context
    for i, finding in enumerate(unique_findings):
        ctx.add(f"exposure_finding_{i}", finding.to_dict())

    ctx.add("exposure_scan", exposure_data)
    ctx.log(f"Exposure scan completed: {len(unique_findings)} findings", level="INFO")

    # Log high-severity findings
    critical_count = sum(
        1 for f in unique_findings if f.severity == ExposureSeverity.CRITICAL
    )
    high_count = sum(1 for f in unique_findings if f.severity == ExposureSeverity.HIGH)
    if critical_count > 0:
        ctx.log(f"CRITICAL: {critical_count} critical exposure(s) found", level="ERROR")
    if high_count > 0:
        ctx.log(f"HIGH: {high_count} high-severity exposure(s) found", level="WARNING")

    return ctx


def analyze_domain_exposure(domain_profile: Dict[str, Any]) -> List[ExposureFinding]:
    """
    Analyze domain profile for exposure indicators.

    Args:
        domain_profile: Domain profile data

    Returns:
        List of exposure findings
    """
    findings = []

    if not domain_profile:
        return findings

    # Check for exposed WHOIS information
    domain_profile.get("registrant_name", "")
    registrant_email = domain_profile.get("registrant_email", "")

    if registrant_email and not registrant_email.startswith("REDACTED"):
        findings.append(
            ExposureFinding(
                title="WHOIS Privacy Not Enabled",
                category=ExposureCategory.INFRASTRUCTURE,
                severity=ExposureSeverity.LOW,
                description="Domain WHOIS information is publicly accessible",
                evidence=[f"Registrant email: {registrant_email}"],
                remediation="Enable WHOIS privacy protection through your registrar",
                affected_assets=[domain_profile.get("domain", "")],
            )
        )

    # Check for internal domains in DNS
    dns_records = domain_profile.get("dns_records", {})
    for record_type, records in dns_records.items():
        if isinstance(records, list):
            for record in records:
                record_str = str(record)
                # Check for internal IP patterns
                for pattern in INFRASTRUCTURE_PATTERNS:
                    if pattern.matches(record_str):
                        findings.append(
                            ExposureFinding(
                                title=pattern.name,
                                category=pattern.category,
                                severity=pattern.severity,
                                description=f"{pattern.description} in {record_type} record",
                                evidence=[f"{record_type}: {record_str}"],
                                remediation=pattern.remediation,
                            )
                        )
                        break

    return findings


def analyze_tech_stack_exposure(tech_stack: Dict[str, Any]) -> List[ExposureFinding]:
    """
    Analyze technology stack for exposure indicators.

    Args:
        tech_stack: Technology stack data

    Returns:
        List of exposure findings
    """
    findings = []

    if not tech_stack:
        return findings

    # Check for version disclosure
    technologies = tech_stack.get("technologies", [])
    for tech in technologies:
        if isinstance(tech, dict):
            name = tech.get("name", "")
            version = tech.get("version", "")
            if version and version != "unknown":
                findings.append(
                    ExposureFinding(
                        title="Technology Version Disclosure",
                        category=ExposureCategory.INFRASTRUCTURE,
                        severity=ExposureSeverity.LOW,
                        description=f"Technology version information exposed: {name} {version}",
                        evidence=[f"{name}: {version}"],
                        remediation="Configure servers to hide version information",
                        metadata={"technology": name, "version": version},
                    )
                )

    # Check for debug headers
    headers = tech_stack.get("headers", {})
    debug_headers = ["X-Debug", "X-Debug-Token", "X-Powered-By", "Server"]
    for header in debug_headers:
        if header.lower() in [h.lower() for h in headers.keys()]:
            value = headers.get(header, "")
            findings.append(
                ExposureFinding(
                    title="Debug/Information Header Exposed",
                    category=ExposureCategory.DEBUG,
                    severity=ExposureSeverity.LOW,
                    description=f"Informational header exposed: {header}",
                    evidence=[f"{header}: {value}"],
                    remediation=f"Remove or hide the {header} header in production",
                )
            )

    return findings


def analyze_code_artifacts_exposure(
    code_artifacts: Dict[str, Any],
) -> List[ExposureFinding]:
    """
    Analyze code artifacts for exposure indicators.

    Args:
        code_artifacts: Code artifacts data

    Returns:
        List of exposure findings
    """
    findings = []

    if not code_artifacts:
        return findings

    # Check for sensitive files in repository
    files = code_artifacts.get("files", [])
    for file_path in files:
        file_str = str(file_path).lower()
        for sensitive_file, (desc, severity) in SENSITIVE_FILES.items():
            if sensitive_file.lower() in file_str:
                findings.append(
                    ExposureFinding(
                        title=f"Sensitive File in Repository: {sensitive_file}",
                        category=ExposureCategory.CONFIGURATION,
                        severity=severity,
                        description=f"{desc} found in code repository",
                        evidence=[str(file_path)],
                        remediation="Remove sensitive files from version control",
                        affected_assets=[str(file_path)],
                    )
                )

    # Check for hardcoded secrets in code
    secrets_found = code_artifacts.get("secrets", [])
    for secret in secrets_found:
        if isinstance(secret, dict):
            secret_type = secret.get("type", "unknown")
            file_path = secret.get("file", "")
            findings.append(
                ExposureFinding(
                    title=f"Hardcoded Secret: {secret_type}",
                    category=ExposureCategory.CREDENTIALS,
                    severity=ExposureSeverity.CRITICAL,
                    description=f"Hardcoded {secret_type} found in source code",
                    evidence=[f"File: {file_path}"],
                    remediation="Remove secrets from source code, use environment variables",
                    affected_assets=[file_path],
                )
            )

    # Check git authors for email exposure
    git_authors = code_artifacts.get("git_authors", [])
    emails_exposed = []
    for author in git_authors:
        if isinstance(author, dict) and author.get("email"):
            emails_exposed.append(author["email"])

    if emails_exposed:
        findings.append(
            ExposureFinding(
                title="Developer Emails in Git History",
                category=ExposureCategory.INFRASTRUCTURE,
                severity=ExposureSeverity.LOW,
                description="Developer email addresses exposed in git commit history",
                evidence=emails_exposed[:5],
                remediation="Consider using private email addresses for git commits",
                metadata={"email_count": len(emails_exposed)},
            )
        )

    return findings


def analyze_document_exposure(doc_metadata: Dict[str, Any]) -> List[ExposureFinding]:
    """
    Analyze document metadata for exposure indicators.

    Args:
        doc_metadata: Document metadata

    Returns:
        List of exposure findings
    """
    findings = []

    if not doc_metadata:
        return findings

    # Check for internal paths in metadata
    internal_paths = doc_metadata.get("internal_paths", [])
    if internal_paths:
        findings.append(
            ExposureFinding(
                title="Internal Paths in Document Metadata",
                category=ExposureCategory.INFRASTRUCTURE,
                severity=ExposureSeverity.LOW,
                description="Document metadata reveals internal file system paths",
                evidence=internal_paths[:5],
                remediation="Strip metadata from documents before publishing",
            )
        )

    # Check for usernames in metadata
    authors = doc_metadata.get("authors", [])
    if authors:
        findings.append(
            ExposureFinding(
                title="Author Information in Document Metadata",
                category=ExposureCategory.INFRASTRUCTURE,
                severity=ExposureSeverity.INFO,
                description="Document metadata contains author information",
                evidence=authors[:5] if isinstance(authors, list) else [str(authors)],
                remediation="Strip author metadata from public documents if sensitive",
            )
        )

    return findings


def analyze_paths_in_context(ctx: Context) -> List[ExposureFinding]:
    """
    Analyze context for exposed path patterns.

    Args:
        ctx: Pipeline context

    Returns:
        List of exposure findings
    """
    findings = []

    # Collect all string data from context
    all_text = []
    for key, value in ctx.data.items():
        if isinstance(value, str):
            all_text.append(value)
        elif isinstance(value, dict):
            all_text.extend(extract_strings_from_dict(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    all_text.append(item)
                elif isinstance(item, dict):
                    all_text.extend(extract_strings_from_dict(item))

    combined_text = " ".join(all_text)

    # Check for exposure patterns
    for pattern in ALL_PATTERNS:
        if pattern.matches(combined_text):
            # Find actual matches for evidence
            matches = re.findall(pattern.pattern, combined_text, re.IGNORECASE)
            if matches:
                unique_matches = list(set(matches[:5]))  # Limit evidence
                findings.append(
                    ExposureFinding(
                        title=pattern.name,
                        category=pattern.category,
                        severity=pattern.severity,
                        description=pattern.description,
                        evidence=unique_matches,
                        remediation=pattern.remediation,
                    )
                )

    return findings


def extract_strings_from_dict(d: Dict[str, Any], max_depth: int = 3) -> List[str]:
    """
    Recursively extract strings from a dictionary.

    Args:
        d: Dictionary to extract from
        max_depth: Maximum recursion depth

    Returns:
        List of strings
    """
    strings = []
    if max_depth <= 0:
        return strings

    for key, value in d.items():
        strings.append(str(key))
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            strings.extend(extract_strings_from_dict(value, max_depth - 1))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    strings.append(item)
                elif isinstance(item, dict):
                    strings.extend(extract_strings_from_dict(item, max_depth - 1))

    return strings


def find_cloud_references(ctx: Context) -> List[Dict[str, Any]]:
    """
    Find cloud storage references in context.

    Args:
        ctx: Pipeline context

    Returns:
        List of cloud storage references
    """
    references = []

    # Patterns for cloud services
    cloud_patterns = [
        (r"s3://([a-zA-Z0-9.-]+)", "AWS S3", "bucket"),
        (r"([a-zA-Z0-9.-]+)\.s3\.amazonaws\.com", "AWS S3", "bucket"),
        (r"([a-zA-Z0-9.-]+)\.blob\.core\.windows\.net", "Azure Blob", "container"),
        (
            r"storage\.googleapis\.com/([a-zA-Z0-9._-]+)",
            "Google Cloud Storage",
            "bucket",
        ),
        (r"gs://([a-zA-Z0-9._-]+)", "Google Cloud Storage", "bucket"),
        (r"([a-zA-Z0-9-]+)\.firebasestorage\.googleapis\.com", "Firebase", "bucket"),
    ]

    # Search all context data
    all_text = []
    for key, value in ctx.data.items():
        if isinstance(value, str):
            all_text.append(value)
        elif isinstance(value, dict):
            all_text.extend(extract_strings_from_dict(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    all_text.append(item)

    combined_text = " ".join(all_text)

    for pattern, provider, resource_type in cloud_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        for match in set(matches):
            references.append(
                {
                    "provider": provider,
                    "resource_type": resource_type,
                    "name": match,
                    "pattern_matched": pattern,
                }
            )

    return references


def generate_cloud_findings(cloud_refs: List[Dict[str, Any]]) -> List[ExposureFinding]:
    """
    Generate findings from cloud references.

    Args:
        cloud_refs: List of cloud references

    Returns:
        List of exposure findings
    """
    findings = []

    if not cloud_refs:
        return findings

    # Group by provider
    by_provider = {}
    for ref in cloud_refs:
        provider = ref["provider"]
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(ref)

    for provider, refs in by_provider.items():
        names = [r["name"] for r in refs]
        findings.append(
            ExposureFinding(
                title=f"{provider} Resources Referenced",
                category=ExposureCategory.CLOUD_STORAGE,
                severity=ExposureSeverity.MEDIUM,
                description=f"{len(refs)} {provider} resource(s) referenced in application",
                evidence=names[:5],
                remediation=f"Verify {provider} resource permissions are properly configured",
                metadata={"provider": provider, "count": len(refs)},
            )
        )

    return findings


def find_credential_exposures(ctx: Context) -> List[Dict[str, Any]]:
    """
    Find credential exposure patterns in context.

    Args:
        ctx: Pipeline context

    Returns:
        List of credential exposures
    """
    exposures = []

    # Credential patterns
    cred_patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"]+)', "Password"),
        (r'(?:api[_-]?key|apikey)\s*[=:]\s*[\'"]?([^\s\'"]+)', "API Key"),
        (r'(?:secret|token)\s*[=:]\s*[\'"]?([^\s\'"]+)', "Secret/Token"),
        (r"Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "JWT Token"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    ]

    # Search all context data
    all_text = []
    for key, value in ctx.data.items():
        if isinstance(value, str):
            all_text.append(value)
        elif isinstance(value, dict):
            all_text.extend(extract_strings_from_dict(value))

    combined_text = " ".join(all_text)

    for pattern, cred_type in cred_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        for match in set(matches):
            # Mask the credential
            if isinstance(match, str) and len(match) > 8:
                masked = match[:4] + "*" * (len(match) - 8) + match[-4:]
            else:
                masked = "****"

            exposures.append(
                {
                    "type": cred_type,
                    "masked_value": masked,
                    "pattern_matched": pattern,
                }
            )

    return exposures


def generate_credential_findings(
    cred_exposures: List[Dict[str, Any]],
) -> List[ExposureFinding]:
    """
    Generate findings from credential exposures.

    Args:
        cred_exposures: List of credential exposures

    Returns:
        List of exposure findings
    """
    findings = []

    if not cred_exposures:
        return findings

    # Group by type
    by_type = {}
    for exp in cred_exposures:
        cred_type = exp["type"]
        if cred_type not in by_type:
            by_type[cred_type] = []
        by_type[cred_type].append(exp)

    for cred_type, exps in by_type.items():
        masked_values = [e["masked_value"] for e in exps]
        findings.append(
            ExposureFinding(
                title=f"{cred_type} Exposure Detected",
                category=ExposureCategory.CREDENTIALS,
                severity=ExposureSeverity.CRITICAL,
                description=f"{len(exps)} potential {cred_type} value(s) found",
                evidence=masked_values[:3],
                remediation=f"Rotate affected {cred_type} immediately and remove from source",
                metadata={"credential_type": cred_type, "count": len(exps)},
            )
        )

    return findings


def identify_public_assets_from_context(ctx: Context) -> List[Dict[str, Any]]:
    """
    Identify public-facing assets from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of public assets
    """
    assets = []

    # From domain profile
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("domain"):
        assets.append(
            {
                "type": "domain",
                "name": domain_profile["domain"],
                "source": "domain_profile",
            }
        )

    # From subdomains
    subdomains = domain_profile.get("subdomains", [])
    for subdomain in subdomains:
        assets.append(
            {
                "type": "subdomain",
                "name": subdomain,
                "source": "domain_enumeration",
            }
        )

    # From tech stack (URLs)
    tech_stack = ctx.get("tech_stack", {})
    urls = tech_stack.get("urls", [])
    for url in urls:
        assets.append(
            {
                "type": "url",
                "name": url,
                "source": "tech_stack",
            }
        )

    # From APIs
    apis = tech_stack.get("apis", [])
    for api in apis:
        assets.append(
            {
                "type": "api",
                "name": api,
                "source": "tech_stack",
            }
        )

    return assets


def find_sensitive_files_in_context(ctx: Context) -> List[Dict[str, Any]]:
    """
    Find sensitive files referenced in context.

    Args:
        ctx: Pipeline context

    Returns:
        List of sensitive files
    """
    sensitive = []

    # Check code artifacts
    code_artifacts = ctx.get("code_artifacts", {})
    files = code_artifacts.get("files", [])

    for file_path in files:
        file_str = str(file_path).lower()
        for sensitive_file, (desc, severity) in SENSITIVE_FILES.items():
            if sensitive_file.lower() in file_str or file_str.endswith(
                sensitive_file.lower()
            ):
                sensitive.append(
                    {
                        "file": str(file_path),
                        "type": sensitive_file,
                        "description": desc,
                        "severity": severity.value,
                    }
                )
                break

    return sensitive


def deduplicate_findings(findings: List[ExposureFinding]) -> List[ExposureFinding]:
    """
    Remove duplicate findings.

    Args:
        findings: List of findings

    Returns:
        Deduplicated list
    """
    seen = set()
    unique = []

    for finding in findings:
        key = (finding.title, finding.category, tuple(sorted(finding.evidence[:3])))
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


def generate_exposure_summary(findings: List[ExposureFinding]) -> Dict[str, Any]:
    """
    Generate summary of exposure findings.

    Args:
        findings: List of findings

    Returns:
        Summary dictionary
    """
    summary = {
        "total_findings": len(findings),
        "by_severity": {},
        "by_category": {},
        "critical_count": 0,
        "high_count": 0,
        "risk_score": 0,
    }

    severity_weights = {
        ExposureSeverity.CRITICAL: 10,
        ExposureSeverity.HIGH: 5,
        ExposureSeverity.MEDIUM: 2,
        ExposureSeverity.LOW: 1,
        ExposureSeverity.INFO: 0,
    }

    for finding in findings:
        # By severity
        sev = finding.severity.value
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        # By category
        cat = finding.category.value
        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        # Counts
        if finding.severity == ExposureSeverity.CRITICAL:
            summary["critical_count"] += 1
        elif finding.severity == ExposureSeverity.HIGH:
            summary["high_count"] += 1

        # Risk score
        summary["risk_score"] += severity_weights.get(finding.severity, 0)

    return summary


# ============================================================================
# Helper Functions
# ============================================================================


def identify_public_assets(target: str) -> List[Dict[str, Any]]:
    """
    Identify public-facing assets for a target.

    Args:
        target: Target domain/organization

    Returns:
        List of identified assets
    """
    assets = []

    # Add the target itself
    assets.append(
        {
            "type": "domain",
            "name": target,
            "source": "target",
        }
    )

    # Common subdomains to check
    common_subdomains = [
        "www",
        "api",
        "app",
        "admin",
        "mail",
        "blog",
        "dev",
        "staging",
        "test",
        "cdn",
        "assets",
    ]

    for sub in common_subdomains:
        assets.append(
            {
                "type": "potential_subdomain",
                "name": f"{sub}.{target}",
                "source": "enumeration",
                "verified": False,
            }
        )

    return assets


def check_information_leakage(target: str) -> List[Finding]:
    """
    Check for information leakage patterns.

    Args:
        target: Target to check

    Returns:
        List of findings
    """
    findings = []

    # Generate potential exposed paths
    for path in COMMON_EXPOSED_PATHS:
        findings.append(
            Finding(
                module="exposure_scan",
                title=f"Potential Exposed Path: {path}",
                description=f"Common sensitive path that should be checked: {target}{path}",
                severity="info",
                data={
                    "category": "information_leakage",
                    "evidence": [f"{target}{path}"],
                    "remediation": "Verify this path is not publicly accessible",
                },
            )
        )

    return findings[:10]  # Limit results


def analyze_employee_profiles(company: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Analyze public employee profile patterns.

    LIMITED TO PUBLIC METADATA ONLY - no scraping.

    Args:
        company: Company name
        limit: Maximum results

    Returns:
        List of profile pattern insights
    """
    profiles = []

    # Common profile patterns (not actual profiles)
    platforms = ["LinkedIn", "GitHub", "Twitter"]

    for platform in platforms:
        profiles.append(
            {
                "platform": platform,
                "search_pattern": f'"{company}" site:{platform.lower()}.com',
                "note": "Use this pattern for manual OSINT",
            }
        )

    return profiles[:limit]


def get_common_exposed_paths() -> List[str]:
    """
    Get list of common exposed paths.

    Returns:
        List of paths
    """
    return COMMON_EXPOSED_PATHS.copy()


def get_sensitive_files() -> Dict[str, Tuple[str, ExposureSeverity]]:
    """
    Get dictionary of sensitive files.

    Returns:
        Dictionary mapping filename to (description, severity)
    """
    return SENSITIVE_FILES.copy()


def get_exposure_patterns() -> List[ExposurePattern]:
    """
    Get all exposure patterns.

    Returns:
        List of exposure patterns
    """
    return ALL_PATTERNS.copy()


def check_path_exposure(path: str) -> Optional[ExposurePattern]:
    """
    Check if a path matches any exposure pattern.

    Args:
        path: Path to check

    Returns:
        Matching pattern or None
    """
    for pattern in ALL_PATTERNS:
        if pattern.matches(path):
            return pattern
    return None
