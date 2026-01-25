"""Tests for corp_assessment/exposure_scan module."""

import pytest
from redops.modules.corp_assessment.exposure_scan import (
    ExposureSeverity,
    ExposureCategory,
    ExposurePattern,
    ExposureFinding,
    SOURCE_CODE_PATTERNS,
    CONFIG_PATTERNS,
    CREDENTIAL_PATTERNS,
    BACKUP_PATTERNS,
    DEBUG_PATTERNS,
    CLOUD_PATTERNS,
    API_PATTERNS,
    ADMIN_PATTERNS,
    INFRASTRUCTURE_PATTERNS,
    ALL_PATTERNS,
    SENSITIVE_FILES,
    COMMON_EXPOSED_PATHS,
    scan_exposure,
    analyze_domain_exposure,
    analyze_tech_stack_exposure,
    analyze_code_artifacts_exposure,
    analyze_document_exposure,
    analyze_paths_in_context,
    find_cloud_references,
    generate_cloud_findings,
    find_credential_exposures,
    generate_credential_findings,
    identify_public_assets_from_context,
    find_sensitive_files_in_context,
    deduplicate_findings,
    generate_exposure_summary,
    extract_strings_from_dict,
    identify_public_assets,
    check_information_leakage,
    analyze_employee_profiles,
    get_common_exposed_paths,
    get_sensitive_files,
    get_exposure_patterns,
    check_path_exposure,
)
from redops.core.context import Context


class TestExposureSeverity:
    """Tests for ExposureSeverity enum."""

    def test_severity_values(self):
        """Test all severity values exist."""
        assert ExposureSeverity.CRITICAL.value == "critical"
        assert ExposureSeverity.HIGH.value == "high"
        assert ExposureSeverity.MEDIUM.value == "medium"
        assert ExposureSeverity.LOW.value == "low"
        assert ExposureSeverity.INFO.value == "info"

    def test_severity_count(self):
        """Test number of severity levels."""
        assert len(ExposureSeverity) == 5


class TestExposureCategory:
    """Tests for ExposureCategory enum."""

    def test_category_values(self):
        """Test all category values exist."""
        assert ExposureCategory.SOURCE_CODE.value == "source_code"
        assert ExposureCategory.CONFIGURATION.value == "configuration"
        assert ExposureCategory.CREDENTIALS.value == "credentials"
        assert ExposureCategory.BACKUP.value == "backup"
        assert ExposureCategory.DEBUG.value == "debug"
        assert ExposureCategory.CLOUD_STORAGE.value == "cloud_storage"
        assert ExposureCategory.API.value == "api"
        assert ExposureCategory.DATABASE.value == "database"
        assert ExposureCategory.ADMIN.value == "admin"
        assert ExposureCategory.DOCUMENTATION.value == "documentation"
        assert ExposureCategory.INFRASTRUCTURE.value == "infrastructure"

    def test_category_count(self):
        """Test number of categories."""
        assert len(ExposureCategory) == 11


class TestExposurePattern:
    """Tests for ExposurePattern dataclass."""

    def test_basic_creation(self):
        """Test basic pattern creation."""
        pattern = ExposurePattern(
            name="Test Pattern",
            pattern=r"\.env$",
            category=ExposureCategory.CONFIGURATION,
            severity=ExposureSeverity.CRITICAL,
            description="Test description",
            remediation="Test remediation",
        )
        assert pattern.name == "Test Pattern"
        assert pattern.category == ExposureCategory.CONFIGURATION
        assert pattern.severity == ExposureSeverity.CRITICAL

    def test_with_indicators(self):
        """Test pattern with indicators."""
        pattern = ExposurePattern(
            name="Git Exposed",
            pattern=r"\.git/",
            category=ExposureCategory.SOURCE_CODE,
            severity=ExposureSeverity.CRITICAL,
            description="Git directory exposed",
            remediation="Block .git access",
            indicators=[".git/HEAD", ".git/config"],
        )
        assert len(pattern.indicators) == 2
        assert ".git/HEAD" in pattern.indicators

    def test_matches_positive(self):
        """Test pattern matching."""
        pattern = ExposurePattern(
            name="Env File",
            pattern=r"\.env$",
            category=ExposureCategory.CONFIGURATION,
            severity=ExposureSeverity.CRITICAL,
            description="Environment file",
            remediation="Remove from public",
        )
        assert pattern.matches("config/.env")
        assert pattern.matches(".env")

    def test_matches_negative(self):
        """Test pattern not matching."""
        pattern = ExposurePattern(
            name="Env File",
            pattern=r"\.env$",
            category=ExposureCategory.CONFIGURATION,
            severity=ExposureSeverity.CRITICAL,
            description="Environment file",
            remediation="Remove from public",
        )
        assert not pattern.matches("environment.txt")
        assert not pattern.matches("env.local")

    def test_matches_case_insensitive(self):
        """Test case-insensitive matching."""
        pattern = ExposurePattern(
            name="Git Exposed",
            pattern=r"\.git/",
            category=ExposureCategory.SOURCE_CODE,
            severity=ExposureSeverity.CRITICAL,
            description="Git directory",
            remediation="Block access",
        )
        assert pattern.matches(".GIT/config")
        assert pattern.matches(".Git/HEAD")


class TestExposureFinding:
    """Tests for ExposureFinding dataclass."""

    def test_basic_creation(self):
        """Test basic finding creation."""
        finding = ExposureFinding(
            title="Test Finding",
            category=ExposureCategory.CREDENTIALS,
            severity=ExposureSeverity.CRITICAL,
            description="Test description",
            evidence=["evidence1"],
            remediation="Fix it",
        )
        assert finding.title == "Test Finding"
        assert finding.category == ExposureCategory.CREDENTIALS
        assert len(finding.evidence) == 1

    def test_with_optional_fields(self):
        """Test finding with optional fields."""
        finding = ExposureFinding(
            title="AWS Key Exposed",
            category=ExposureCategory.CREDENTIALS,
            severity=ExposureSeverity.CRITICAL,
            description="AWS key found",
            evidence=["AKIA..."],
            remediation="Rotate key",
            affected_assets=["app.js", "config.js"],
            metadata={"key_type": "access_key"},
        )
        assert len(finding.affected_assets) == 2
        assert finding.metadata["key_type"] == "access_key"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        finding = ExposureFinding(
            title="Test",
            category=ExposureCategory.DEBUG,
            severity=ExposureSeverity.HIGH,
            description="Debug endpoint",
            evidence=["/debug"],
            remediation="Disable in prod",
        )
        result = finding.to_dict()

        assert result["title"] == "Test"
        assert result["category"] == "debug"
        assert result["severity"] == "high"
        assert "/debug" in result["evidence"]

    def test_to_finding(self):
        """Test conversion to Finding model."""
        exposure = ExposureFinding(
            title="Critical Issue",
            category=ExposureCategory.CREDENTIALS,
            severity=ExposureSeverity.CRITICAL,
            description="Password exposed",
            evidence=["password=***"],
            remediation="Remove password",
        )
        finding = exposure.to_finding()

        assert finding.title == "Critical Issue"
        assert finding.severity == "critical"
        assert finding.module == "exposure_scan"
        assert finding.data["category"] == "credentials"
        assert "password=***" in finding.data["evidence"]


class TestSourceCodePatterns:
    """Tests for source code exposure patterns."""

    def test_git_pattern(self):
        """Test Git repository pattern."""
        git_pattern = next(p for p in SOURCE_CODE_PATTERNS if "Git" in p.name)
        assert git_pattern.matches("/.git/config")
        assert git_pattern.matches(".git/HEAD")
        assert git_pattern.severity == ExposureSeverity.CRITICAL

    def test_svn_pattern(self):
        """Test SVN repository pattern."""
        svn_pattern = next(p for p in SOURCE_CODE_PATTERNS if "SVN" in p.name)
        assert svn_pattern.matches("/.svn/entries")
        assert svn_pattern.severity == ExposureSeverity.HIGH

    def test_source_map_pattern(self):
        """Test source map pattern."""
        map_pattern = next(p for p in SOURCE_CODE_PATTERNS if "Map" in p.name)
        assert map_pattern.matches("app.js.map")
        assert map_pattern.matches("styles.css.map")


class TestConfigPatterns:
    """Tests for configuration exposure patterns."""

    def test_env_pattern(self):
        """Test environment file pattern."""
        env_pattern = next(p for p in CONFIG_PATTERNS if "Environment" in p.name)
        assert env_pattern.matches(".env")
        assert env_pattern.matches(".env.local")
        assert env_pattern.matches(".env.production")
        assert env_pattern.severity == ExposureSeverity.CRITICAL

    def test_docker_pattern(self):
        """Test Docker configuration pattern."""
        docker_pattern = next(p for p in CONFIG_PATTERNS if "Docker" in p.name)
        assert docker_pattern.matches("docker-compose.yml")
        assert docker_pattern.matches("Dockerfile")


class TestCredentialPatterns:
    """Tests for credential exposure patterns."""

    def test_private_key_pattern(self):
        """Test private key pattern."""
        key_pattern = next(p for p in CREDENTIAL_PATTERNS if "Private Key" in p.name)
        assert key_pattern.matches("server.pem")
        assert key_pattern.matches("id_rsa")
        assert key_pattern.severity == ExposureSeverity.CRITICAL

    def test_aws_credentials_pattern(self):
        """Test AWS credentials pattern."""
        aws_pattern = next(p for p in CREDENTIAL_PATTERNS if "AWS" in p.name)
        assert aws_pattern.matches("aws_access_key=AKIAIOSFODNN7EXAMPLE")
        assert aws_pattern.matches("AKIAIOSFODNN7EXAMPLE")

    def test_database_connection_pattern(self):
        """Test database connection string pattern."""
        db_pattern = next(p for p in CREDENTIAL_PATTERNS if "Database Connection" in p.name)
        assert db_pattern.matches("mysql://user:pass@host/db")
        assert db_pattern.matches("postgres://admin:secret@localhost")


class TestBackupPatterns:
    """Tests for backup file patterns."""

    def test_backup_file_pattern(self):
        """Test backup file pattern."""
        backup_pattern = next(p for p in BACKUP_PATTERNS if p.name == "Backup File Exposed")
        assert backup_pattern.matches("config.bak")
        assert backup_pattern.matches("data.backup")
        assert backup_pattern.matches("old.orig")

    def test_database_dump_pattern(self):
        """Test database dump pattern."""
        dump_pattern = next(p for p in BACKUP_PATTERNS if "Database Dump" in p.name)
        assert dump_pattern.matches("backup.sql")
        assert dump_pattern.matches("database.dump")
        assert dump_pattern.severity == ExposureSeverity.CRITICAL


class TestDebugPatterns:
    """Tests for debug/development patterns."""

    def test_debug_endpoint_pattern(self):
        """Test debug endpoint pattern."""
        debug_pattern = next(p for p in DEBUG_PATTERNS if "Debug Endpoint" in p.name)
        assert debug_pattern.matches("/debug/")
        assert debug_pattern.matches("/phpinfo")
        assert debug_pattern.matches("/server-status")

    def test_log_files_pattern(self):
        """Test log files pattern."""
        log_pattern = next(p for p in DEBUG_PATTERNS if "Log Files" in p.name)
        assert log_pattern.matches("error.log")
        assert log_pattern.matches("/logs/")


class TestCloudPatterns:
    """Tests for cloud storage patterns."""

    def test_s3_pattern(self):
        """Test AWS S3 pattern."""
        s3_pattern = next(p for p in CLOUD_PATTERNS if "S3" in p.name)
        assert s3_pattern.matches("mybucket.s3.amazonaws.com")
        assert s3_pattern.matches("s3://mybucket/file")

    def test_azure_pattern(self):
        """Test Azure Blob pattern."""
        azure_pattern = next(p for p in CLOUD_PATTERNS if "Azure" in p.name)
        assert azure_pattern.matches("myaccount.blob.core.windows.net")

    def test_gcs_pattern(self):
        """Test Google Cloud Storage pattern."""
        gcs_pattern = next(p for p in CLOUD_PATTERNS if "Google Cloud" in p.name)
        assert gcs_pattern.matches("storage.googleapis.com")
        assert gcs_pattern.matches("gs://mybucket")


class TestApiPatterns:
    """Tests for API exposure patterns."""

    def test_graphql_pattern(self):
        """Test GraphQL endpoint pattern."""
        graphql_pattern = next(p for p in API_PATTERNS if "GraphQL" in p.name)
        assert graphql_pattern.matches("/graphql")
        assert graphql_pattern.matches("/graphiql")

    def test_swagger_pattern(self):
        """Test Swagger/OpenAPI pattern."""
        swagger_pattern = next(p for p in API_PATTERNS if "Swagger" in p.name)
        assert swagger_pattern.matches("/swagger")
        assert swagger_pattern.matches("/api-docs")


class TestAdminPatterns:
    """Tests for admin/management patterns."""

    def test_admin_panel_pattern(self):
        """Test admin panel pattern."""
        admin_pattern = next(p for p in ADMIN_PATTERNS if p.name == "Admin Panel")
        assert admin_pattern.matches("/admin")
        assert admin_pattern.matches("/wp-admin")

    def test_database_admin_pattern(self):
        """Test database admin pattern."""
        db_admin = next(p for p in ADMIN_PATTERNS if "Database Admin" in p.name)
        assert db_admin.matches("/phpmyadmin")
        assert db_admin.matches("/adminer")


class TestInfrastructurePatterns:
    """Tests for infrastructure patterns."""

    def test_internal_ip_pattern(self):
        """Test internal IP address pattern."""
        ip_pattern = next(p for p in INFRASTRUCTURE_PATTERNS if "Internal IP" in p.name)
        assert ip_pattern.matches("10.0.0.1")
        assert ip_pattern.matches("192.168.1.100")
        assert ip_pattern.matches("172.16.0.1")

    def test_server_version_pattern(self):
        """Test server version disclosure pattern."""
        version_pattern = next(p for p in INFRASTRUCTURE_PATTERNS if "Server Version" in p.name)
        assert version_pattern.matches("Apache/2.4.41")
        assert version_pattern.matches("nginx/1.18.0")


class TestAllPatterns:
    """Tests for combined patterns."""

    def test_all_patterns_combined(self):
        """Test that all patterns are included."""
        total = (
            len(SOURCE_CODE_PATTERNS) +
            len(CONFIG_PATTERNS) +
            len(CREDENTIAL_PATTERNS) +
            len(BACKUP_PATTERNS) +
            len(DEBUG_PATTERNS) +
            len(CLOUD_PATTERNS) +
            len(API_PATTERNS) +
            len(ADMIN_PATTERNS) +
            len(INFRASTRUCTURE_PATTERNS)
        )
        assert len(ALL_PATTERNS) == total

    def test_all_patterns_have_required_fields(self):
        """Test that all patterns have required fields."""
        for pattern in ALL_PATTERNS:
            assert pattern.name
            assert pattern.pattern
            assert pattern.category
            assert pattern.severity
            assert pattern.description
            assert pattern.remediation


class TestSensitiveFiles:
    """Tests for sensitive files dictionary."""

    def test_env_files(self):
        """Test environment files are defined."""
        assert ".env" in SENSITIVE_FILES
        assert ".env.local" in SENSITIVE_FILES
        assert SENSITIVE_FILES[".env"][1] == ExposureSeverity.CRITICAL

    def test_key_files(self):
        """Test key files are defined."""
        assert "id_rsa" in SENSITIVE_FILES
        assert SENSITIVE_FILES["id_rsa"][1] == ExposureSeverity.CRITICAL

    def test_backup_files(self):
        """Test backup files are defined."""
        assert "backup.sql" in SENSITIVE_FILES
        assert SENSITIVE_FILES["backup.sql"][1] == ExposureSeverity.CRITICAL


class TestCommonExposedPaths:
    """Tests for common exposed paths."""

    def test_version_control_paths(self):
        """Test version control paths are included."""
        assert "/.git/" in COMMON_EXPOSED_PATHS
        assert "/.svn/" in COMMON_EXPOSED_PATHS

    def test_config_paths(self):
        """Test configuration paths are included."""
        assert "/.env" in COMMON_EXPOSED_PATHS
        assert "/config.php" in COMMON_EXPOSED_PATHS

    def test_admin_paths(self):
        """Test admin paths are included."""
        assert "/admin/" in COMMON_EXPOSED_PATHS
        assert "/phpmyadmin/" in COMMON_EXPOSED_PATHS


class TestScanExposure:
    """Tests for scan_exposure function."""

    def test_empty_context(self):
        """Test scan with empty context."""
        ctx = Context(target="example.com")
        result = scan_exposure(ctx)

        assert "exposure_scan" in result.data
        exposure = result.get("exposure_scan")
        assert exposure["target"] == "example.com"
        assert "findings" in exposure
        assert "summary" in exposure

    def test_no_target_warning(self):
        """Test warning when no target specified."""
        ctx = Context(target="")
        result = scan_exposure(ctx)

        # Should log warning
        warnings = result.get_logs(level="WARNING")
        assert len(warnings) >= 1

    def test_with_domain_profile(self):
        """Test scan with domain profile data."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {
            "domain": "example.com",
            "registrant_email": "admin@example.com",
        })

        result = scan_exposure(ctx)
        exposure = result.get("exposure_scan")

        # Should detect WHOIS exposure
        assert len(exposure["findings"]) >= 1

    def test_with_attack_paths(self):
        """Test scan with attack path data containing patterns."""
        ctx = Context(target="example.com")
        ctx.add("attack_paths", [
            {"url": "https://example.com/.git/config"},
            {"url": "https://example.com/.env"},
        ])

        result = scan_exposure(ctx)
        exposure = result.get("exposure_scan")

        # Should detect git and env exposure
        assert len(exposure["findings"]) >= 1

    def test_min_severity_filter(self):
        """Test minimum severity filtering."""
        ctx = Context(target="example.com")
        ctx.add("tech_stack", {
            "technologies": [{"name": "Apache", "version": "2.4.41"}],
        })

        # Without filter - should include low severity
        result1 = scan_exposure(ctx)
        exposure1 = result1.get("exposure_scan")

        # With high min severity - should exclude low
        result2 = scan_exposure(ctx, {"min_severity": "high"})
        exposure2 = result2.get("exposure_scan")

        assert len(exposure2["findings"]) <= len(exposure1["findings"])

    def test_category_filter(self):
        """Test category filtering."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {
            "registrant_email": "admin@example.com",
        })
        ctx.add("code_artifacts", {
            "files": [".env", "id_rsa"],
        })

        result = scan_exposure(ctx, {"categories": ["credentials"]})
        exposure = result.get("exposure_scan")

        # Should only have credential findings
        for finding in exposure["findings"]:
            assert finding["category"] == "credentials"

    def test_exposure_summary(self):
        """Test exposure summary generation."""
        ctx = Context(target="example.com")
        ctx.add("code_artifacts", {
            "files": [".env", "id_rsa", "backup.sql"],
            "secrets": [{"type": "api_key", "file": "config.js"}],
        })

        result = scan_exposure(ctx)
        exposure = result.get("exposure_scan")

        assert "summary" in exposure
        assert "total_findings" in exposure["summary"]
        assert "by_severity" in exposure["summary"]
        assert "by_category" in exposure["summary"]
        assert "risk_score" in exposure["summary"]


class TestAnalyzeDomainExposure:
    """Tests for analyze_domain_exposure function."""

    def test_empty_profile(self):
        """Test with empty domain profile."""
        findings = analyze_domain_exposure({})
        assert findings == []

    def test_whois_exposure(self):
        """Test WHOIS information exposure detection."""
        profile = {
            "domain": "example.com",
            "registrant_email": "admin@example.com",
        }
        findings = analyze_domain_exposure(profile)

        assert len(findings) >= 1
        whois_finding = next((f for f in findings if "WHOIS" in f.title), None)
        assert whois_finding is not None

    def test_redacted_whois(self):
        """Test redacted WHOIS is not flagged."""
        profile = {
            "domain": "example.com",
            "registrant_email": "REDACTED FOR PRIVACY",
        }
        findings = analyze_domain_exposure(profile)

        whois_finding = next((f for f in findings if "WHOIS" in f.title), None)
        assert whois_finding is None

    def test_internal_ip_in_dns(self):
        """Test internal IP detection in DNS records."""
        profile = {
            "domain": "example.com",
            "dns_records": {
                "A": ["192.168.1.100", "1.2.3.4"],
            }
        }
        findings = analyze_domain_exposure(profile)

        ip_finding = next((f for f in findings if "Internal IP" in f.title), None)
        assert ip_finding is not None


class TestAnalyzeTechStackExposure:
    """Tests for analyze_tech_stack_exposure function."""

    def test_empty_tech_stack(self):
        """Test with empty tech stack."""
        findings = analyze_tech_stack_exposure({})
        assert findings == []

    def test_version_disclosure(self):
        """Test technology version disclosure detection."""
        tech_stack = {
            "technologies": [
                {"name": "Apache", "version": "2.4.41"},
                {"name": "PHP", "version": "7.4.3"},
            ]
        }
        findings = analyze_tech_stack_exposure(tech_stack)

        assert len(findings) >= 2
        assert all("Version" in f.title for f in findings)

    def test_debug_headers(self):
        """Test debug header detection."""
        tech_stack = {
            "headers": {
                "X-Powered-By": "PHP/7.4.3",
                "Server": "Apache/2.4.41",
            }
        }
        findings = analyze_tech_stack_exposure(tech_stack)

        assert len(findings) >= 1
        assert any("Header" in f.title for f in findings)


class TestAnalyzeCodeArtifactsExposure:
    """Tests for analyze_code_artifacts_exposure function."""

    def test_empty_artifacts(self):
        """Test with empty code artifacts."""
        findings = analyze_code_artifacts_exposure({})
        assert findings == []

    def test_sensitive_files_detection(self):
        """Test sensitive file detection in repository."""
        artifacts = {
            "files": [".env", "config/secrets.yml", "id_rsa"],
        }
        findings = analyze_code_artifacts_exposure(artifacts)

        assert len(findings) >= 2
        assert any(".env" in f.title for f in findings)

    def test_hardcoded_secrets(self):
        """Test hardcoded secrets detection."""
        artifacts = {
            "secrets": [
                {"type": "API Key", "file": "src/config.js"},
                {"type": "Password", "file": "src/db.py"},
            ]
        }
        findings = analyze_code_artifacts_exposure(artifacts)

        assert len(findings) >= 2
        assert all(f.severity == ExposureSeverity.CRITICAL for f in findings)

    def test_git_author_emails(self):
        """Test developer email detection in git history."""
        artifacts = {
            "git_authors": [
                {"name": "John Doe", "email": "john@company.com"},
                {"name": "Jane Smith", "email": "jane@company.com"},
            ]
        }
        findings = analyze_code_artifacts_exposure(artifacts)

        assert len(findings) >= 1
        assert any("Email" in f.title for f in findings)


class TestAnalyzeDocumentExposure:
    """Tests for analyze_document_exposure function."""

    def test_empty_metadata(self):
        """Test with empty document metadata."""
        findings = analyze_document_exposure({})
        assert findings == []

    def test_internal_paths(self):
        """Test internal path detection in metadata."""
        metadata = {
            "internal_paths": [
                "/home/user/projects/app/doc.pdf",
                "C:\\Users\\admin\\Documents\\report.docx",
            ]
        }
        findings = analyze_document_exposure(metadata)

        assert len(findings) >= 1
        assert any("Internal Paths" in f.title for f in findings)

    def test_author_information(self):
        """Test author information detection."""
        metadata = {
            "authors": ["John Doe", "Jane Smith"],
        }
        findings = analyze_document_exposure(metadata)

        assert len(findings) >= 1
        assert any("Author" in f.title for f in findings)


class TestAnalyzePathsInContext:
    """Tests for analyze_paths_in_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        findings = analyze_paths_in_context(ctx)
        assert findings == []

    def test_git_path_detection(self):
        """Test Git path detection in context."""
        ctx = Context(target="example.com")
        ctx.add("urls", ["https://example.com/.git/config"])

        findings = analyze_paths_in_context(ctx)

        assert len(findings) >= 1
        assert any("Git" in f.title for f in findings)

    def test_multiple_pattern_detection(self):
        """Test multiple pattern detection."""
        ctx = Context(target="example.com")
        ctx.add("data", {
            "paths": [
                "/.git/HEAD",
                "/.env",
                "/admin/login",
                "/api/v1/users",
            ]
        })

        findings = analyze_paths_in_context(ctx)
        assert len(findings) >= 3


class TestFindCloudReferences:
    """Tests for find_cloud_references function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        refs = find_cloud_references(ctx)
        assert refs == []

    def test_s3_reference(self):
        """Test S3 reference detection."""
        ctx = Context(target="example.com")
        ctx.add("config", "https://mybucket.s3.amazonaws.com/file.txt")

        refs = find_cloud_references(ctx)

        assert len(refs) >= 1
        assert any(r["provider"] == "AWS S3" for r in refs)

    def test_azure_reference(self):
        """Test Azure Blob reference detection."""
        ctx = Context(target="example.com")
        ctx.add("storage_url", "https://myaccount.blob.core.windows.net/container")

        refs = find_cloud_references(ctx)

        assert len(refs) >= 1
        assert any(r["provider"] == "Azure Blob" for r in refs)

    def test_gcs_reference(self):
        """Test Google Cloud Storage reference detection."""
        ctx = Context(target="example.com")
        ctx.add("bucket", "gs://my-bucket/path/file")

        refs = find_cloud_references(ctx)

        assert len(refs) >= 1
        assert any(r["provider"] == "Google Cloud Storage" for r in refs)

    def test_firebase_reference(self):
        """Test Firebase reference detection."""
        ctx = Context(target="example.com")
        ctx.add("firebase", "myapp.firebasestorage.googleapis.com")

        refs = find_cloud_references(ctx)

        assert len(refs) >= 1
        assert any(r["provider"] == "Firebase" for r in refs)


class TestGenerateCloudFindings:
    """Tests for generate_cloud_findings function."""

    def test_empty_refs(self):
        """Test with empty references."""
        findings = generate_cloud_findings([])
        assert findings == []

    def test_grouped_by_provider(self):
        """Test findings are grouped by provider."""
        refs = [
            {"provider": "AWS S3", "resource_type": "bucket", "name": "bucket1"},
            {"provider": "AWS S3", "resource_type": "bucket", "name": "bucket2"},
            {"provider": "Azure Blob", "resource_type": "container", "name": "container1"},
        ]
        findings = generate_cloud_findings(refs)

        assert len(findings) == 2  # AWS and Azure
        aws_finding = next(f for f in findings if "AWS" in f.title)
        assert "2" in aws_finding.description


class TestFindCredentialExposures:
    """Tests for find_credential_exposures function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        exposures = find_credential_exposures(ctx)
        assert exposures == []

    def test_aws_key_detection(self):
        """Test AWS access key detection."""
        ctx = Context(target="example.com")
        ctx.add("config", "aws_key = AKIAIOSFODNN7EXAMPLE")

        exposures = find_credential_exposures(ctx)

        assert len(exposures) >= 1
        assert any(e["type"] == "AWS Access Key ID" for e in exposures)

    def test_password_detection(self):
        """Test password detection."""
        ctx = Context(target="example.com")
        ctx.add("config", 'password = "mysecretpassword"')

        exposures = find_credential_exposures(ctx)

        assert len(exposures) >= 1
        assert any(e["type"] == "Password" for e in exposures)

    def test_api_key_detection(self):
        """Test API key detection."""
        ctx = Context(target="example.com")
        ctx.add("settings", "api_key=abc123xyz789")

        exposures = find_credential_exposures(ctx)

        assert len(exposures) >= 1
        assert any(e["type"] == "API Key" for e in exposures)

    def test_credential_masking(self):
        """Test that credentials are masked."""
        ctx = Context(target="example.com")
        ctx.add("config", "password=supersecretpassword123")

        exposures = find_credential_exposures(ctx)

        for exposure in exposures:
            if exposure["type"] == "Password":
                # Should contain asterisks
                assert "*" in exposure["masked_value"]
                # Should not contain the full password
                assert "supersecretpassword123" not in exposure["masked_value"]


class TestGenerateCredentialFindings:
    """Tests for generate_credential_findings function."""

    def test_empty_exposures(self):
        """Test with empty exposures."""
        findings = generate_credential_findings([])
        assert findings == []

    def test_grouped_by_type(self):
        """Test findings are grouped by credential type."""
        exposures = [
            {"type": "Password", "masked_value": "****", "pattern_matched": ""},
            {"type": "Password", "masked_value": "****", "pattern_matched": ""},
            {"type": "API Key", "masked_value": "****", "pattern_matched": ""},
        ]
        findings = generate_credential_findings(exposures)

        assert len(findings) == 2  # Password and API Key
        password_finding = next(f for f in findings if "Password" in f.title)
        assert "2" in password_finding.description


class TestIdentifyPublicAssets:
    """Tests for identify_public_assets_from_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        assets = identify_public_assets_from_context(ctx)
        assert assets == []

    def test_domain_from_profile(self):
        """Test domain extraction from profile."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {"domain": "example.com"})

        assets = identify_public_assets_from_context(ctx)

        assert len(assets) >= 1
        assert any(a["type"] == "domain" for a in assets)

    def test_subdomains(self):
        """Test subdomain extraction."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
        })

        assets = identify_public_assets_from_context(ctx)

        subdomain_assets = [a for a in assets if a["type"] == "subdomain"]
        assert len(subdomain_assets) == 2


class TestFindSensitiveFilesInContext:
    """Tests for find_sensitive_files_in_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        files = find_sensitive_files_in_context(ctx)
        assert files == []

    def test_sensitive_file_detection(self):
        """Test sensitive file detection."""
        ctx = Context(target="example.com")
        ctx.add("code_artifacts", {
            "files": [".env", "config/database.yml", "id_rsa"],
        })

        files = find_sensitive_files_in_context(ctx)

        assert len(files) >= 2
        assert any(f["type"] == ".env" for f in files)


class TestDeduplicateFindings:
    """Tests for deduplicate_findings function."""

    def test_empty_list(self):
        """Test with empty list."""
        result = deduplicate_findings([])
        assert result == []

    def test_remove_duplicates(self):
        """Test duplicate removal."""
        findings = [
            ExposureFinding(
                title="Git Exposed",
                category=ExposureCategory.SOURCE_CODE,
                severity=ExposureSeverity.CRITICAL,
                description="Git repo exposed",
                evidence=["/.git/"],
                remediation="Block access",
            ),
            ExposureFinding(
                title="Git Exposed",
                category=ExposureCategory.SOURCE_CODE,
                severity=ExposureSeverity.CRITICAL,
                description="Git repo exposed",
                evidence=["/.git/"],
                remediation="Block access",
            ),
        ]

        result = deduplicate_findings(findings)
        assert len(result) == 1

    def test_keep_unique(self):
        """Test that unique findings are kept."""
        findings = [
            ExposureFinding(
                title="Finding 1",
                category=ExposureCategory.SOURCE_CODE,
                severity=ExposureSeverity.CRITICAL,
                description="Desc 1",
                evidence=["evidence1"],
                remediation="Fix 1",
            ),
            ExposureFinding(
                title="Finding 2",
                category=ExposureCategory.CONFIGURATION,
                severity=ExposureSeverity.HIGH,
                description="Desc 2",
                evidence=["evidence2"],
                remediation="Fix 2",
            ),
        ]

        result = deduplicate_findings(findings)
        assert len(result) == 2


class TestGenerateExposureSummary:
    """Tests for generate_exposure_summary function."""

    def test_empty_findings(self):
        """Test with empty findings."""
        summary = generate_exposure_summary([])

        assert summary["total_findings"] == 0
        assert summary["critical_count"] == 0
        assert summary["risk_score"] == 0

    def test_severity_counts(self):
        """Test severity counting."""
        findings = [
            ExposureFinding(
                title="Critical 1",
                category=ExposureCategory.CREDENTIALS,
                severity=ExposureSeverity.CRITICAL,
                description="",
                evidence=[],
                remediation="",
            ),
            ExposureFinding(
                title="Critical 2",
                category=ExposureCategory.CREDENTIALS,
                severity=ExposureSeverity.CRITICAL,
                description="",
                evidence=[],
                remediation="",
            ),
            ExposureFinding(
                title="High 1",
                category=ExposureCategory.SOURCE_CODE,
                severity=ExposureSeverity.HIGH,
                description="",
                evidence=[],
                remediation="",
            ),
        ]

        summary = generate_exposure_summary(findings)

        assert summary["total_findings"] == 3
        assert summary["critical_count"] == 2
        assert summary["high_count"] == 1
        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 1

    def test_category_counts(self):
        """Test category counting."""
        findings = [
            ExposureFinding(
                title="Cred 1",
                category=ExposureCategory.CREDENTIALS,
                severity=ExposureSeverity.CRITICAL,
                description="",
                evidence=[],
                remediation="",
            ),
            ExposureFinding(
                title="Cred 2",
                category=ExposureCategory.CREDENTIALS,
                severity=ExposureSeverity.HIGH,
                description="",
                evidence=[],
                remediation="",
            ),
            ExposureFinding(
                title="Source 1",
                category=ExposureCategory.SOURCE_CODE,
                severity=ExposureSeverity.CRITICAL,
                description="",
                evidence=[],
                remediation="",
            ),
        ]

        summary = generate_exposure_summary(findings)

        assert summary["by_category"]["credentials"] == 2
        assert summary["by_category"]["source_code"] == 1

    def test_risk_score(self):
        """Test risk score calculation."""
        findings = [
            ExposureFinding(
                title="Critical",
                category=ExposureCategory.CREDENTIALS,
                severity=ExposureSeverity.CRITICAL,  # weight 10
                description="",
                evidence=[],
                remediation="",
            ),
            ExposureFinding(
                title="High",
                category=ExposureCategory.SOURCE_CODE,
                severity=ExposureSeverity.HIGH,  # weight 5
                description="",
                evidence=[],
                remediation="",
            ),
        ]

        summary = generate_exposure_summary(findings)

        assert summary["risk_score"] == 15  # 10 + 5


class TestExtractStringsFromDict:
    """Tests for extract_strings_from_dict function."""

    def test_simple_dict(self):
        """Test simple dictionary extraction."""
        d = {"key1": "value1", "key2": "value2"}
        strings = extract_strings_from_dict(d)

        assert "key1" in strings
        assert "value1" in strings
        assert "key2" in strings
        assert "value2" in strings

    def test_nested_dict(self):
        """Test nested dictionary extraction."""
        d = {
            "outer": {
                "inner": "nested_value",
            }
        }
        strings = extract_strings_from_dict(d)

        assert "outer" in strings
        assert "inner" in strings
        assert "nested_value" in strings

    def test_list_values(self):
        """Test list value extraction."""
        d = {
            "items": ["item1", "item2", "item3"],
        }
        strings = extract_strings_from_dict(d)

        assert "item1" in strings
        assert "item2" in strings
        assert "item3" in strings

    def test_max_depth(self):
        """Test max depth limiting."""
        d = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": "deep_value",
                    }
                }
            }
        }
        strings = extract_strings_from_dict(d, max_depth=2)

        # Should not reach level4 with depth 2
        assert "deep_value" not in strings


class TestIdentifyPublicAssets:
    """Tests for identify_public_assets helper function."""

    def test_basic_identification(self):
        """Test basic asset identification."""
        assets = identify_public_assets("example.com")

        assert len(assets) >= 1
        # Should include target domain
        domain_asset = next(a for a in assets if a["type"] == "domain")
        assert domain_asset["name"] == "example.com"

    def test_common_subdomains(self):
        """Test common subdomain generation."""
        assets = identify_public_assets("example.com")

        subdomain_assets = [a for a in assets if a["type"] == "potential_subdomain"]
        assert len(subdomain_assets) >= 5

        # Should include common subdomains
        names = [a["name"] for a in subdomain_assets]
        assert "www.example.com" in names
        assert "api.example.com" in names


class TestCheckInformationLeakage:
    """Tests for check_information_leakage function."""

    def test_generates_findings(self):
        """Test that findings are generated."""
        findings = check_information_leakage("example.com")

        assert len(findings) >= 1
        assert len(findings) <= 10  # Should be limited

    def test_finding_structure(self):
        """Test finding structure."""
        findings = check_information_leakage("example.com")

        for finding in findings:
            assert finding.title
            assert finding.description
            assert finding.severity == "info"
            assert finding.module == "exposure_scan"


class TestAnalyzeEmployeeProfiles:
    """Tests for analyze_employee_profiles function."""

    def test_returns_patterns(self):
        """Test that search patterns are returned."""
        profiles = analyze_employee_profiles("Acme Corp")

        assert len(profiles) >= 1

    def test_platform_coverage(self):
        """Test platform coverage."""
        profiles = analyze_employee_profiles("Acme Corp")

        platforms = [p["platform"] for p in profiles]
        assert "LinkedIn" in platforms
        assert "GitHub" in platforms

    def test_limit_parameter(self):
        """Test limit parameter."""
        profiles = analyze_employee_profiles("Acme Corp", limit=2)
        assert len(profiles) <= 2


class TestGetCommonExposedPaths:
    """Tests for get_common_exposed_paths function."""

    def test_returns_copy(self):
        """Test that a copy is returned."""
        paths1 = get_common_exposed_paths()
        paths2 = get_common_exposed_paths()

        # Modifying one should not affect other
        paths1.append("/test/")
        assert "/test/" not in paths2

    def test_contains_paths(self):
        """Test that paths are returned."""
        paths = get_common_exposed_paths()
        assert len(paths) > 0
        assert "/.git/" in paths


class TestGetSensitiveFiles:
    """Tests for get_sensitive_files function."""

    def test_returns_copy(self):
        """Test that a copy is returned."""
        files1 = get_sensitive_files()
        files2 = get_sensitive_files()

        # Modifying one should not affect other
        files1["test"] = ("Test", ExposureSeverity.LOW)
        assert "test" not in files2

    def test_contains_files(self):
        """Test that files are returned."""
        files = get_sensitive_files()
        assert len(files) > 0
        assert ".env" in files


class TestGetExposurePatterns:
    """Tests for get_exposure_patterns function."""

    def test_returns_copy(self):
        """Test that a copy is returned."""
        patterns1 = get_exposure_patterns()
        patterns2 = get_exposure_patterns()

        assert len(patterns1) == len(patterns2)

    def test_contains_patterns(self):
        """Test that patterns are returned."""
        patterns = get_exposure_patterns()
        assert len(patterns) > 0


class TestCheckPathExposure:
    """Tests for check_path_exposure function."""

    def test_matches_git(self):
        """Test matching git path."""
        pattern = check_path_exposure("/.git/config")

        assert pattern is not None
        assert pattern.category == ExposureCategory.SOURCE_CODE

    def test_matches_env(self):
        """Test matching env file."""
        pattern = check_path_exposure("/.env")

        assert pattern is not None
        assert pattern.category == ExposureCategory.CONFIGURATION

    def test_no_match(self):
        """Test non-matching path."""
        pattern = check_path_exposure("/index.html")

        assert pattern is None

    def test_matches_admin(self):
        """Test matching admin path."""
        pattern = check_path_exposure("/phpmyadmin/")

        assert pattern is not None
        assert pattern.category == ExposureCategory.ADMIN


class TestIntegration:
    """Integration tests for exposure scanning."""

    def test_full_scan_with_all_data_types(self):
        """Test full scan with various context data."""
        ctx = Context(target="example.com")

        # Add domain profile
        ctx.add("domain_profile", {
            "domain": "example.com",
            "registrant_email": "admin@example.com",
            "dns_records": {"A": ["1.2.3.4"]},
        })

        # Add tech stack
        ctx.add("tech_stack", {
            "technologies": [{"name": "nginx", "version": "1.18.0"}],
            "headers": {"Server": "nginx/1.18.0"},
        })

        # Add code artifacts
        ctx.add("code_artifacts", {
            "files": [".env", ".git/config"],
            "secrets": [{"type": "API Key", "file": "config.js"}],
        })

        # Add cloud references
        ctx.add("storage_config", "s3://mybucket/data")

        result = scan_exposure(ctx)
        exposure = result.get("exposure_scan")

        # Should have multiple findings
        assert len(exposure["findings"]) >= 3

        # Should have summary
        assert exposure["summary"]["total_findings"] >= 3

        # Should have various categories
        categories = exposure["summary"]["by_category"]
        assert len(categories) >= 2

    def test_critical_findings_logged(self):
        """Test that critical findings are logged."""
        ctx = Context(target="example.com")
        ctx.add("code_artifacts", {
            "secrets": [
                {"type": "AWS Key", "file": "config.js"},
                {"type": "Password", "file": "db.py"},
            ],
        })

        result = scan_exposure(ctx)

        # Should have error logs for critical findings
        errors = result.get_logs(level="ERROR")
        assert len(errors) >= 1

    def test_finding_deduplication_in_scan(self):
        """Test that duplicate findings are removed during scan."""
        ctx = Context(target="example.com")

        # Add duplicate data
        ctx.add("path1", "/.git/config")
        ctx.add("path2", "/.git/HEAD")
        ctx.add("data", {"paths": ["/.git/", "/.git/objects"]})

        result = scan_exposure(ctx)
        exposure = result.get("exposure_scan")

        # Should have only one git-related finding
        git_findings = [f for f in exposure["findings"] if "Git" in f["title"]]
        assert len(git_findings) == 1
