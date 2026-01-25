"""Tests for cli/app module."""

import json
from pathlib import Path
from unittest.mock import MagicMock
from redops.cli.app import (
    OutputFormat,
    Verbosity,
    ScanPreset,
    CLIConfig,
    ScanResult,
    SCAN_PRESETS,
    AVAILABLE_MODULES,
    cmd_scan,
    cmd_report,
    cmd_modules,
    cmd_presets,
    cmd_config,
    cmd_version,
    execute_scan,
    count_findings,
    save_scan_output,
    generate_report,
    generate_executive_text_report,
    get_config_path,
    get_default_config,
    print_header,
    print_error,
    print_scan_summary,
    create_parser,
    main,
)
from redops.core.context import Context


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_format_values(self):
        """Test format values."""
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.HTML.value == "html"
        assert OutputFormat.MARKDOWN.value == "markdown"
        assert OutputFormat.TEXT.value == "text"


class TestVerbosity:
    """Tests for Verbosity enum."""

    def test_verbosity_levels(self):
        """Test verbosity levels."""
        assert Verbosity.QUIET.value == 0
        assert Verbosity.NORMAL.value == 1
        assert Verbosity.VERBOSE.value == 2
        assert Verbosity.DEBUG.value == 3


class TestScanPreset:
    """Tests for ScanPreset enum."""

    def test_preset_values(self):
        """Test preset values."""
        assert ScanPreset.QUICK.value == "quick"
        assert ScanPreset.FULL.value == "full"
        assert ScanPreset.RECON.value == "recon"
        assert ScanPreset.COMPLIANCE.value == "compliance"


class TestCLIConfig:
    """Tests for CLIConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = CLIConfig()

        assert config.verbosity == Verbosity.NORMAL
        assert config.output_format == OutputFormat.TEXT
        assert config.output_dir == "./output"
        assert config.quiet is False
        assert config.dry_run is False

    def test_custom_config(self):
        """Test custom configuration."""
        config = CLIConfig(
            verbosity=Verbosity.DEBUG,
            output_format=OutputFormat.JSON,
            quiet=True,
        )

        assert config.verbosity == Verbosity.DEBUG
        assert config.output_format == OutputFormat.JSON
        assert config.quiet is True


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        result = ScanResult(
            success=True,
            target="example.com",
            preset="quick",
            modules_run=["domain_profile"],
            findings_count=5,
            duration_seconds=10.5,
            output_files=["/path/to/output.json"],
            errors=[],
        )

        assert result.success is True
        assert result.findings_count == 5

    def test_to_dict(self):
        """Test to_dict method."""
        result = ScanResult(
            success=True,
            target="example.com",
            preset="quick",
            modules_run=["mod1"],
            findings_count=3,
            duration_seconds=5.0,
            output_files=[],
            errors=[],
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["target"] == "example.com"
        assert d["findings_count"] == 3


class TestScanPresets:
    """Tests for scan presets."""

    def test_presets_defined(self):
        """Test all presets are defined."""
        assert ScanPreset.QUICK in SCAN_PRESETS
        assert ScanPreset.FULL in SCAN_PRESETS
        assert ScanPreset.RECON in SCAN_PRESETS

    def test_preset_structure(self):
        """Test preset structure."""
        for preset, info in SCAN_PRESETS.items():
            assert "name" in info
            assert "description" in info
            assert "modules" in info
            assert "estimated_time" in info
            assert isinstance(info["modules"], list)

    def test_preset_modules_exist(self):
        """Test preset modules exist in available modules."""
        for preset, info in SCAN_PRESETS.items():
            for module in info["modules"]:
                assert module in AVAILABLE_MODULES, (
                    f"Module {module} in preset {preset} not available"
                )


class TestAvailableModules:
    """Tests for available modules."""

    def test_modules_defined(self):
        """Test modules are defined."""
        assert "domain_profile" in AVAILABLE_MODULES
        assert "exposure_scan" in AVAILABLE_MODULES
        assert "correlation" in AVAILABLE_MODULES
        assert "executive_report" in AVAILABLE_MODULES

    def test_module_structure(self):
        """Test module structure."""
        for mod_id, info in AVAILABLE_MODULES.items():
            assert "name" in info
            assert "description" in info
            assert "category" in info


class TestCmdModules:
    """Tests for cmd_modules command."""

    def test_modules_text_output(self, capsys):
        """Test modules command with text output."""
        args = MagicMock()
        config = CLIConfig(quiet=False, output_format=OutputFormat.TEXT)

        result = cmd_modules(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "domain_profile" in captured.out

    def test_modules_json_output(self, capsys):
        """Test modules command with JSON output."""
        args = MagicMock()
        config = CLIConfig(output_format=OutputFormat.JSON, quiet=True)

        result = cmd_modules(args, config)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "domain_profile" in output


class TestCmdPresets:
    """Tests for cmd_presets command."""

    def test_presets_text_output(self, capsys):
        """Test presets command with text output."""
        args = MagicMock()
        config = CLIConfig(quiet=False, output_format=OutputFormat.TEXT)

        result = cmd_presets(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "quick" in captured.out
        assert "full" in captured.out

    def test_presets_json_output(self, capsys):
        """Test presets command with JSON output."""
        args = MagicMock()
        config = CLIConfig(output_format=OutputFormat.JSON, quiet=True)

        result = cmd_presets(args, config)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "quick" in output
        assert "full" in output


class TestCmdVersion:
    """Tests for cmd_version command."""

    def test_version_text(self, capsys):
        """Test version command with text output."""
        args = MagicMock()
        config = CLIConfig(output_format=OutputFormat.TEXT)

        result = cmd_version(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "RedOPS" in captured.out

    def test_version_json(self, capsys):
        """Test version command with JSON output."""
        args = MagicMock()
        config = CLIConfig(output_format=OutputFormat.JSON)

        result = cmd_version(args, config)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "name" in output
        assert output["name"] == "RedOPS"


class TestCmdScan:
    """Tests for cmd_scan command."""

    def test_dry_run(self, capsys):
        """Test scan dry run."""
        args = MagicMock()
        args.target = "example.com"
        args.preset = "quick"
        args.modules = None
        config = CLIConfig(dry_run=True, quiet=False)

        result = cmd_scan(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out

    def test_with_custom_modules(self, capsys):
        """Test scan with custom modules."""
        args = MagicMock()
        args.target = "example.com"
        args.preset = "quick"
        args.modules = "domain_profile,exposure_scan"
        config = CLIConfig(dry_run=True, quiet=False)

        result = cmd_scan(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "domain_profile" in captured.out


class TestExecuteScan:
    """Tests for execute_scan function."""

    def test_basic_execution(self):
        """Test basic scan execution."""
        config = CLIConfig(quiet=True, output_dir=None)

        result = execute_scan("example.com", ["domain_profile"], config)

        assert isinstance(result, ScanResult)
        assert result.target == "example.com"

    def test_handles_errors(self):
        """Test error handling."""
        config = CLIConfig(quiet=True, output_dir=None)

        # Using a non-existent module should handle gracefully
        result = execute_scan("example.com", ["nonexistent_module"], config)

        assert isinstance(result, ScanResult)


class TestCountFindings:
    """Tests for count_findings function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")

        count = count_findings(ctx)

        assert count == 0

    def test_with_findings(self):
        """Test with findings."""
        ctx = Context(target="example.com")
        ctx.add("exposure_scan", {"exposures": [{"title": "Exp1"}, {"title": "Exp2"}]})
        ctx.add("threat_intel", {"iocs": [{"value": "1.2.3.4"}]})

        count = count_findings(ctx)

        assert count == 3


class TestSaveOutput:
    """Tests for save_scan_output function."""

    def test_saves_json(self, tmp_path):
        """Test saving JSON output."""
        ctx = Context(target="example.com")
        ctx.add("test_data", {"key": "value"})
        config = CLIConfig(output_dir=str(tmp_path))

        files = save_scan_output(ctx, config)

        assert len(files) >= 1
        assert Path(files[0]).exists()

    def test_saves_executive_report(self, tmp_path):
        """Test saving executive report."""
        ctx = Context(target="example.com")
        ctx.add("executive_report", {"summary": "test"})
        config = CLIConfig(output_dir=str(tmp_path))

        files = save_scan_output(ctx, config)

        assert len(files) >= 2  # Main JSON + report


class TestGenerateReport:
    """Tests for generate_report function."""

    def test_json_report(self):
        """Test JSON report generation."""
        data = {"key": "value"}
        config = CLIConfig()

        report = generate_report(data, "json", config)

        parsed = json.loads(report)
        assert parsed["key"] == "value"

    def test_summary_report(self):
        """Test summary report generation."""
        data = {
            "exposure_scan": {"exposures": [{"title": "Test"}]},
            "threat_intel": {"iocs": []},
            "compliance": {"gaps": []},
            "correlations": {"correlations": [], "insights": []},
        }
        config = CLIConfig()

        report = generate_report(data, "summary", config)

        assert "SCAN SUMMARY" in report
        assert "Exposures: 1" in report


class TestGenerateExecutiveTextReport:
    """Tests for generate_executive_text_report function."""

    def test_basic_report(self):
        """Test basic executive report."""
        data = {
            "executive_report": {
                "executive_summary": {
                    "target": "example.com",
                    "generated_at": "2025-01-01",
                    "overall_risk_level": "high",
                    "risk_score": 75,
                    "executive_brief": "Test brief",
                    "key_findings": [
                        {"title": "Finding 1", "severity": "high"},
                    ],
                },
                "recommendations": [
                    {"title": "Rec 1", "priority": "critical"},
                ],
            }
        }

        report = generate_executive_text_report(data)

        assert "EXECUTIVE SECURITY ASSESSMENT REPORT" in report
        assert "example.com" in report
        assert "HIGH" in report


class TestGetConfigPath:
    """Tests for get_config_path function."""

    def test_returns_path(self):
        """Test returns Path object."""
        path = get_config_path()

        assert isinstance(path, Path)
        assert "redops" in str(path).lower()

    def test_env_override(self, monkeypatch):
        """Test environment variable override."""
        monkeypatch.setenv("REDOPS_CONFIG", "/custom/path/config.json")

        path = get_config_path()

        assert str(path) == "/custom/path/config.json"


class TestGetDefaultConfig:
    """Tests for get_default_config function."""

    def test_config_structure(self):
        """Test default config structure."""
        config = get_default_config()

        assert "output_dir" in config
        assert "verbosity" in config
        assert "modules" in config
        assert "api_keys" in config

    def test_modules_enabled(self):
        """Test modules are enabled by default."""
        config = get_default_config()

        assert "enabled" in config["modules"]
        assert len(config["modules"]["enabled"]) > 0


class TestPrintFunctions:
    """Tests for print functions."""

    def test_print_header(self, capsys):
        """Test print_header."""
        print_header("Test Header")

        captured = capsys.readouterr()
        assert "Test Header" in captured.out
        assert "=" in captured.out

    def test_print_error(self, capsys):
        """Test print_error."""
        print_error("Test error message")

        captured = capsys.readouterr()
        assert "ERROR" in captured.err
        assert "Test error message" in captured.err

    def test_print_scan_summary(self, capsys):
        """Test print_scan_summary."""
        result = ScanResult(
            success=True,
            target="example.com",
            preset="quick",
            modules_run=["mod1"],
            findings_count=5,
            duration_seconds=10.0,
            output_files=[],
            errors=[],
        )

        print_scan_summary(result)

        captured = capsys.readouterr()
        assert "SUCCESS" in captured.out
        assert "example.com" in captured.out


class TestCreateParser:
    """Tests for create_parser function."""

    def test_parser_creation(self):
        """Test parser is created."""
        parser = create_parser()

        assert parser is not None
        assert parser.prog == "redops"

    def test_scan_subcommand(self):
        """Test scan subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["scan", "example.com"])

        assert args.command == "scan"
        assert args.target == "example.com"

    def test_scan_with_preset(self):
        """Test scan with preset."""
        parser = create_parser()
        args = parser.parse_args(["scan", "example.com", "--preset", "full"])

        assert args.preset == "full"

    def test_scan_with_modules(self):
        """Test scan with modules."""
        parser = create_parser()
        args = parser.parse_args(
            ["scan", "example.com", "-m", "domain_profile,exposure_scan"]
        )

        assert args.modules == "domain_profile,exposure_scan"

    def test_modules_subcommand(self):
        """Test modules subcommand."""
        parser = create_parser()
        args = parser.parse_args(["modules"])

        assert args.command == "modules"

    def test_presets_subcommand(self):
        """Test presets subcommand."""
        parser = create_parser()
        args = parser.parse_args(["presets"])

        assert args.command == "presets"

    def test_version_subcommand(self):
        """Test version subcommand."""
        parser = create_parser()
        args = parser.parse_args(["version"])

        assert args.command == "version"

    def test_global_options(self):
        """Test global options."""
        parser = create_parser()
        args = parser.parse_args(["-v", "-v", "--quiet", "--dry-run", "modules"])

        assert args.verbose == 2
        assert args.quiet is True
        assert args.dry_run is True


class TestMain:
    """Tests for main function."""

    def test_modules_command(self, capsys):
        """Test main with modules command."""
        result = main(["modules"])

        assert result == 0
        captured = capsys.readouterr()
        assert "domain_profile" in captured.out

    def test_presets_command(self, capsys):
        """Test main with presets command."""
        result = main(["presets"])

        assert result == 0
        captured = capsys.readouterr()
        assert "quick" in captured.out

    def test_version_command(self, capsys):
        """Test main with version command."""
        result = main(["version"])

        assert result == 0
        captured = capsys.readouterr()
        assert "RedOPS" in captured.out

    def test_no_command(self, capsys):
        """Test main with no command shows help."""
        result = main([])

        assert result == 1  # Should show help and exit with error

    def test_dry_run_scan(self, capsys):
        """Test dry run scan."""
        result = main(["--dry-run", "scan", "example.com"])

        assert result == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out

    def test_json_output_format(self, capsys):
        """Test JSON output format."""
        result = main(["-q", "-f", "json", "modules"])

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert isinstance(output, dict)


class TestCmdConfig:
    """Tests for cmd_config command."""

    def test_config_path(self, capsys):
        """Test config path action."""
        args = MagicMock()
        args.action = "path"
        args.force = False
        config = CLIConfig()

        result = cmd_config(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "redops" in captured.out.lower()

    def test_config_show_missing(self, capsys):
        """Test config show when file doesn't exist."""
        args = MagicMock()
        args.action = "show"
        config = CLIConfig(config_file="/nonexistent/path/config.json")

        result = cmd_config(args, config)

        assert result == 0


class TestCmdReport:
    """Tests for cmd_report command."""

    def test_missing_input(self, capsys):
        """Test report with missing input file."""
        args = MagicMock()
        args.input = "/nonexistent/file.json"
        args.type = "summary"
        args.output = None
        config = CLIConfig(quiet=False)

        result = cmd_report(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_report_generation(self, tmp_path, capsys):
        """Test report generation from file."""
        # Create input file
        input_file = tmp_path / "scan.json"
        input_file.write_text(
            json.dumps(
                {
                    "exposure_scan": {"exposures": []},
                    "threat_intel": {"iocs": []},
                    "compliance": {"gaps": []},
                    "correlations": {"correlations": [], "insights": []},
                }
            )
        )

        args = MagicMock()
        args.input = str(input_file)
        args.type = "summary"
        args.output = None
        config = CLIConfig(quiet=False)

        result = cmd_report(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "SCAN SUMMARY" in captured.out


class TestIntegration:
    """Integration tests for CLI."""

    def test_full_scan_flow_dry_run(self, capsys):
        """Test full scan flow in dry run mode."""
        result = main(
            ["--dry-run", "-f", "text", "scan", "example.com", "--preset", "full"]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out
        assert "domain_profile" in captured.out

    def test_quiet_mode(self, capsys):
        """Test quiet mode suppresses output."""
        result = main(["--quiet", "--dry-run", "scan", "example.com"])

        assert result == 0
        # Quiet mode should have minimal output
        captured = capsys.readouterr()
        # Dry run still prints something
        assert len(captured.out) < 500

    def test_verbosity_levels(self, capsys):
        """Test different verbosity levels work."""
        # Normal
        main(["modules"])
        normal = len(capsys.readouterr().out)

        # Verbose (should be same or more)
        main(["-v", "modules"])
        verbose = len(capsys.readouterr().out)

        # Both should produce output
        assert normal > 0
        assert verbose > 0
