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
        assert ScanPreset.AI_ENHANCED in SCAN_PRESETS

    def test_ai_enhanced_preset(self):
        """Test ai_enhanced preset includes AI modules."""
        preset = SCAN_PRESETS[ScanPreset.AI_ENHANCED]
        assert "ai_analyze" in preset["modules"]
        assert "ai_recommend" in preset["modules"]
        assert preset["name"] == "AI-Enhanced Assessment"

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


class TestCmdScanAdvanced:
    """Additional tests for cmd_scan command."""

    def test_no_valid_modules(self, capsys):
        """Test scan with no valid modules returns error."""
        args = MagicMock()
        args.target = "example.com"
        args.preset = "quick"
        args.modules = "nonexistent_module,another_fake"
        config = CLIConfig(quiet=False, dry_run=False)

        result = cmd_scan(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "No valid modules" in captured.err


class TestCmdReportAdvanced:
    """Additional tests for cmd_report command."""

    def test_invalid_json_file(self, tmp_path, capsys):
        """Test report with invalid JSON file."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not valid json {{{")

        args = MagicMock()
        args.input = str(invalid_file)
        args.type = "summary"
        args.output = None
        config = CLIConfig(quiet=False)

        result = cmd_report(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid JSON" in captured.err

    def test_report_to_output_file(self, tmp_path, capsys):
        """Test report generation to output file."""
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
        output_file = tmp_path / "output" / "report.txt"

        args = MagicMock()
        args.input = str(input_file)
        args.type = "summary"
        args.output = str(output_file)
        config = CLIConfig(quiet=False)

        result = cmd_report(args, config)

        assert result == 0
        assert output_file.exists()
        captured = capsys.readouterr()
        assert "Report saved" in captured.out


class TestCmdConfigAdvanced:
    """Additional tests for cmd_config command."""

    def test_config_show_existing(self, tmp_path, capsys, monkeypatch):
        """Test config show with existing file."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"test": "value"}))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "show"
        config = CLIConfig()

        result = cmd_config(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "test" in captured.out

    def test_config_init_new(self, tmp_path, capsys, monkeypatch):
        """Test config init creates new file."""
        config_file = tmp_path / "new_config.json"
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "init"
        args.force = False
        config = CLIConfig()

        result = cmd_config(args, config)

        assert result == 0
        assert config_file.exists()
        captured = capsys.readouterr()
        assert "initialized" in captured.out

    def test_config_init_existing_no_force(self, tmp_path, capsys, monkeypatch):
        """Test config init with existing file without force."""
        config_file = tmp_path / "existing_config.json"
        config_file.write_text("{}")
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "init"
        args.force = False
        config = CLIConfig()

        result = cmd_config(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "already exists" in captured.err

    def test_config_init_with_force(self, tmp_path, capsys, monkeypatch):
        """Test config init with force overwrites."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"old": "data"}')
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "init"
        args.force = True
        config = CLIConfig()

        result = cmd_config(args, config)

        assert result == 0
        # Should have new default config, not old data
        new_config = json.loads(config_file.read_text())
        assert "old" not in new_config


class TestCmdSettings:
    """Tests for cmd_settings command."""

    def test_settings_opens_menu(self, tmp_path, monkeypatch):
        """Test settings command opens menu."""
        from unittest.mock import patch

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        config = CLIConfig(quiet=True)

        with patch(
            "redops.cli.settings.run_settings_menu", return_value=0
        ) as mock_menu:
            from redops.cli.app import cmd_settings

            result = cmd_settings(args, config)

        assert result == 0
        mock_menu.assert_called_once_with(quiet=True)


class TestCmdApikey:
    """Tests for cmd_apikey command."""

    def test_apikey_list(self, tmp_path, capsys, monkeypatch):
        """Test apikey list command."""
        from redops.cli.app import cmd_apikey

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "list"
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "API Keys" in captured.out

    def test_apikey_set_no_provider(self, capsys):
        """Test apikey set without provider."""
        from redops.cli.app import cmd_apikey

        args = MagicMock()
        args.action = "set"
        args.provider = None
        args.key = None
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Provider is required" in captured.err

    def test_apikey_set_with_key(self, tmp_path, capsys, monkeypatch):
        """Test apikey set with provider and key."""
        from redops.cli.app import cmd_apikey

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "set"
        args.provider = "openai"
        args.key = "test-key-123"
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 0

    def test_apikey_set_empty_key(self, capsys):
        """Test apikey set with empty key."""
        from redops.cli.app import cmd_apikey
        from unittest.mock import patch

        args = MagicMock()
        args.action = "set"
        args.provider = "openai"
        args.key = None
        config = CLIConfig()

        with patch("getpass.getpass", return_value=""):
            result = cmd_apikey(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.err

    def test_apikey_get_no_provider(self, capsys):
        """Test apikey get without provider."""
        from redops.cli.app import cmd_apikey

        args = MagicMock()
        args.action = "get"
        args.provider = None
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Provider is required" in captured.err

    def test_apikey_get_with_key(self, tmp_path, capsys, monkeypatch):
        """Test apikey get with configured key."""
        from redops.cli.app import cmd_apikey

        config_data = get_default_config()
        config_data["api_keys"]["shodan"] = "test-shodan-key"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "get"
        args.provider = "shodan"
        args.show = False
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "shodan" in captured.out
        assert "*" in captured.out  # Masked

    def test_apikey_get_with_show(self, tmp_path, capsys, monkeypatch):
        """Test apikey get with --show flag."""
        from redops.cli.app import cmd_apikey

        config_data = get_default_config()
        config_data["api_keys"]["shodan"] = "test-shodan-key-full"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "get"
        args.provider = "shodan"
        args.show = True
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "test-shodan-key-full" in captured.out

    def test_apikey_get_not_set(self, tmp_path, capsys, monkeypatch):
        """Test apikey get when not set."""
        from redops.cli.app import cmd_apikey

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "get"
        args.provider = "shodan"
        args.show = False
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "not set" in captured.out

    def test_apikey_remove_no_provider(self, capsys):
        """Test apikey remove without provider."""
        from redops.cli.app import cmd_apikey

        args = MagicMock()
        args.action = "remove"
        args.provider = None
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Provider is required" in captured.err

    def test_apikey_remove(self, tmp_path, capsys, monkeypatch):
        """Test apikey remove command."""
        from redops.cli.app import cmd_apikey

        config_data = get_default_config()
        config_data["api_keys"]["shodan"] = "to-remove"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        monkeypatch.setenv("REDOPS_CONFIG", str(config_file))

        args = MagicMock()
        args.action = "remove"
        args.provider = "shodan"
        config = CLIConfig()

        result = cmd_apikey(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "removed" in captured.out


class TestGenerateReportBranches:
    """Tests for generate_report branches."""

    def test_executive_report(self):
        """Test executive report type."""
        data = {
            "executive_report": {
                "executive_summary": {
                    "target": "test.com",
                    "overall_risk_level": "medium",
                    "risk_score": 50,
                    "key_findings": [],
                },
                "recommendations": [],
            }
        }
        config = CLIConfig()

        report = generate_report(data, "executive", config)

        assert "EXECUTIVE" in report
        assert "test.com" in report

    def test_technical_report(self):
        """Test technical report type."""
        data = {"technical": "data"}
        config = CLIConfig()

        report = generate_report(data, "technical", config)

        parsed = json.loads(report)
        assert parsed["technical"] == "data"

    def test_unknown_report_type(self):
        """Test unknown report type falls back to JSON."""
        data = {"unknown": "type"}
        config = CLIConfig()

        report = generate_report(data, "unknown_type", config)

        parsed = json.loads(report)
        assert parsed["unknown"] == "type"


class TestPrintFunctionsAdvanced:
    """Additional tests for print functions."""

    def test_print_warning(self, capsys):
        """Test print_warning."""
        from redops.cli.app import print_warning

        print_warning("Test warning")

        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "Test warning" in captured.out

    def test_print_info(self, capsys):
        """Test print_info."""
        from redops.cli.app import print_info

        print_info("Test info")

        captured = capsys.readouterr()
        assert "INFO" in captured.out
        assert "Test info" in captured.out

    def test_print_success(self, capsys):
        """Test print_success."""
        from redops.cli.app import print_success

        print_success("Test success")

        captured = capsys.readouterr()
        assert "SUCCESS" in captured.out
        assert "Test success" in captured.out

    def test_print_progress(self, capsys):
        """Test print_progress."""
        from redops.cli.app import print_progress

        print_progress("Running module...")

        captured = capsys.readouterr()
        assert "->" in captured.out
        assert "Running module" in captured.out

    def test_print_scan_results(self, capsys):
        """Test print_scan_results."""
        from redops.cli.app import print_scan_results

        result = ScanResult(
            success=True,
            target="example.com",
            preset="quick",
            modules_run=["mod1", "mod2"],
            findings_count=5,
            duration_seconds=15.5,
            output_files=["/path/to/output.json"],
            errors=["Error 1"],
        )
        config = CLIConfig()

        print_scan_results(result, config)

        captured = capsys.readouterr()
        assert "SCAN RESULTS" in captured.out
        assert "SUCCESS" in captured.out
        assert "example.com" in captured.out
        assert "mod1" in captured.out
        assert "Errors" in captured.out

    def test_print_scan_results_failed(self, capsys):
        """Test print_scan_results with failed scan."""
        from redops.cli.app import print_scan_results

        result = ScanResult(
            success=False,
            target="example.com",
            preset="quick",
            modules_run=[],
            findings_count=0,
            duration_seconds=1.0,
            output_files=[],
            errors=["Critical error"],
        )
        config = CLIConfig()

        print_scan_results(result, config)

        captured = capsys.readouterr()
        assert "FAILED" in captured.out


class TestGetPluginDirectories:
    """Tests for get_plugin_directories function."""

    def test_returns_list(self, tmp_path, monkeypatch):
        """Test returns a list."""
        from redops.cli.app import get_plugin_directories

        # Clear env var
        monkeypatch.delenv("REDOPS_PLUGIN_PATH", raising=False)

        result = get_plugin_directories()

        assert isinstance(result, list)

    def test_includes_user_dir_if_exists(self, tmp_path, monkeypatch):
        """Test includes user plugin dir if it exists."""
        from redops.cli.app import get_plugin_directories

        # Create user plugin dir
        user_dir = tmp_path / ".config" / "redops" / "plugins"
        user_dir.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.delenv("REDOPS_PLUGIN_PATH", raising=False)

        result = get_plugin_directories()

        assert user_dir in result

    def test_includes_env_path(self, tmp_path, monkeypatch):
        """Test includes REDOPS_PLUGIN_PATH directories."""
        from redops.cli.app import get_plugin_directories

        plugin_dir = tmp_path / "custom_plugins"
        plugin_dir.mkdir()
        monkeypatch.setenv("REDOPS_PLUGIN_PATH", str(plugin_dir))

        result = get_plugin_directories()

        assert plugin_dir in result


class TestExecuteScanAdvanced:
    """Additional tests for execute_scan function."""

    def test_with_debug_verbosity(self):
        """Test execute_scan with debug verbosity."""
        config = CLIConfig(quiet=True, output_dir=None, verbosity=Verbosity.DEBUG)

        # Even with error, should not crash
        result = execute_scan("example.com", ["nonexistent"], config)

        assert isinstance(result, ScanResult)

    def test_saves_output_when_dir_set(self, tmp_path):
        """Test execute_scan saves output when output_dir is set."""
        config = CLIConfig(quiet=True, output_dir=str(tmp_path))

        result = execute_scan("example.com", ["domain_profile"], config)

        assert len(result.output_files) >= 1
        for output_file in result.output_files:
            assert Path(output_file).exists()


class TestParserAdvanced:
    """Additional parser tests."""

    def test_report_subcommand(self):
        """Test report subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["report", "scan.json", "-t", "executive"])

        assert args.command == "report"
        assert args.input == "scan.json"
        assert args.type == "executive"

    def test_config_subcommand(self):
        """Test config subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["config", "init", "--force"])

        assert args.command == "config"
        assert args.action == "init"
        assert args.force is True

    def test_settings_subcommand(self):
        """Test settings subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["settings"])

        assert args.command == "settings"

    def test_apikey_subcommand(self):
        """Test apikey subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["apikey", "set", "-p", "openai", "-k", "key123"])

        assert args.command == "apikey"
        assert args.action == "set"
        assert args.provider == "openai"
        assert args.key == "key123"

    def test_ai_subcommand(self):
        """Test ai subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["ai", "analyze", "-i", "scan.json"])

        assert args.command == "ai"
        assert args.action == "analyze"
        assert args.input == "scan.json"

    def test_history_subcommand(self):
        """Test history subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["history", "list", "--limit", "10"])

        assert args.command == "history"
        assert args.action == "list"
        assert args.limit == 10

    def test_plugin_subcommand(self):
        """Test plugin subcommand parsing."""
        parser = create_parser()
        args = parser.parse_args(["plugin", "list"])

        assert args.command == "plugin"
        assert args.action == "list"


class TestCmdAi:
    """Tests for cmd_ai command."""

    def test_ai_init_error(self, capsys):
        """Test AI command when assistant fails to initialize."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "analyze"
        args.provider = None
        args.model = None
        args.input = None
        config = CLIConfig()

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = cmd_ai(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed to initialize" in captured.err

    def test_ai_analyze_no_input(self, capsys):
        """Test AI analyze without input file."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "analyze"
        args.provider = None
        args.model = None
        args.input = None
        config = CLIConfig()

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Input file required" in captured.err

    def test_ai_analyze_success(self, tmp_path, capsys):
        """Test AI analyze with valid input."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        input_file = tmp_path / "scan.json"
        input_file.write_text(json.dumps({"findings": []}))

        args = MagicMock()
        args.action = "analyze"
        args.provider = None
        args.model = None
        args.input = str(input_file)
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Analysis result"
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "Analysis result" in captured.out

    def test_ai_explain_no_query(self, capsys):
        """Test AI explain without query."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "explain"
        args.provider = None
        args.model = None
        args.query = None
        args.context = None
        config = CLIConfig()

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Query required" in captured.err

    def test_ai_explain_success(self, capsys):
        """Test AI explain with query."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "explain"
        args.provider = None
        args.model = None
        args.query = "What is XSS?"
        args.context = None
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "XSS explanation"
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "XSS explanation" in captured.out

    def test_ai_explain_with_context(self, tmp_path, capsys):
        """Test AI explain with context file."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        context_file = tmp_path / "context.json"
        context_file.write_text(json.dumps({"extra": "info"}))

        args = MagicMock()
        args.action = "explain"
        args.provider = None
        args.model = None
        args.query = "What is this?"
        args.context = str(context_file)
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "Contextual explanation"
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 0

    def test_ai_suggest_no_input(self, capsys):
        """Test AI suggest without input file."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "suggest"
        args.provider = None
        args.model = None
        args.input = None
        config = CLIConfig()

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 1

    def test_ai_suggest_success(self, tmp_path, capsys):
        """Test AI suggest with valid input."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        input_file = tmp_path / "scan.json"
        input_file.write_text(json.dumps({"findings": []}))

        args = MagicMock()
        args.action = "suggest"
        args.provider = None
        args.model = None
        args.input = str(input_file)
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        mock_assistant.suggest_remediations.return_value = "Suggestions"
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 0

    def test_ai_summarize_success(self, tmp_path, capsys):
        """Test AI summarize with valid input."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        input_file = tmp_path / "scan.json"
        input_file.write_text(json.dumps({"findings": []}))

        args = MagicMock()
        args.action = "summarize"
        args.provider = None
        args.model = None
        args.input = str(input_file)
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "Summary"
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = cmd_ai(args, config)

        assert result == 0

    def test_ai_chat_exit(self, capsys):
        """Test AI chat with exit."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "chat"
        args.provider = None
        args.model = None
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            with patch("builtins.input", side_effect=["exit"]):
                result = cmd_ai(args, config)

        assert result == 0

    def test_ai_chat_quit(self, capsys):
        """Test AI chat with quit."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "chat"
        args.provider = None
        args.model = None
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            with patch("builtins.input", side_effect=["quit"]):
                result = cmd_ai(args, config)

        assert result == 0

    def test_ai_chat_eof(self, capsys):
        """Test AI chat with EOF."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "chat"
        args.provider = None
        args.model = None
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            with patch("builtins.input", side_effect=EOFError):
                result = cmd_ai(args, config)

        assert result == 0

    def test_ai_chat_interaction(self, capsys):
        """Test AI chat with user interaction."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        args = MagicMock()
        args.action = "chat"
        args.provider = None
        args.model = None
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        mock_assistant.chat.return_value = "AI response"
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            with patch("builtins.input", side_effect=["Hello", "", "exit"]):
                result = cmd_ai(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "AI response" in captured.out

    def test_ai_chat_load_file(self, tmp_path, capsys):
        """Test AI chat load command."""
        from redops.cli.app import cmd_ai
        from unittest.mock import patch

        context_file = tmp_path / "context.json"
        context_file.write_text(json.dumps({"data": "loaded"}))

        args = MagicMock()
        args.action = "chat"
        args.provider = None
        args.model = None
        config = CLIConfig(quiet=True)

        mock_assistant = MagicMock()
        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            with patch("builtins.input", side_effect=[f"load {context_file}", "exit"]):
                result = cmd_ai(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "Loaded context" in captured.out


class TestCmdHistory:
    """Tests for cmd_history command."""

    def test_history_list_empty(self, capsys):
        """Test history list with no scans."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "list"
        args.target = None
        args.status = None
        args.limit = 20
        config = CLIConfig()

        mock_db = MagicMock()
        mock_db.list_scans.return_value = []
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "No scans found" in captured.out

    def test_history_list_with_results(self, capsys):
        """Test history list with scans."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "list"
        args.target = None
        args.status = None
        args.limit = 20
        config = CLIConfig()

        mock_scan = MagicMock()
        mock_scan.id = 1
        mock_scan.status = "completed"
        mock_scan.target = "example.com"
        mock_scan.findings_count = 5
        mock_scan.started_at = "2025-01-01T00:00:00"

        mock_db = MagicMock()
        mock_db.list_scans.return_value = [mock_scan]
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    def test_history_list_json(self, capsys):
        """Test history list with JSON output."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "list"
        args.target = None
        args.status = None
        args.limit = 20
        config = CLIConfig(output_format=OutputFormat.JSON)

        mock_scan = MagicMock()
        mock_scan.to_dict.return_value = {"id": 1, "target": "test.com"}

        mock_db = MagicMock()
        mock_db.list_scans.return_value = [mock_scan]
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output[0]["target"] == "test.com"

    def test_history_show_no_id(self, capsys):
        """Test history show without ID."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "show"
        args.id = None
        config = CLIConfig()

        mock_db = MagicMock()
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "Scan ID required" in captured.err

    def test_history_show_not_found(self, capsys):
        """Test history show with non-existent scan."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "show"
        args.id = 999
        config = CLIConfig()

        mock_db = MagicMock()
        mock_db.get_scan.return_value = None
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_history_show_success(self, capsys):
        """Test history show with valid scan."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "show"
        args.id = 1
        config = CLIConfig()

        mock_scan = MagicMock()
        mock_scan.id = 1
        mock_scan.target = "example.com"
        mock_scan.preset = "quick"
        mock_scan.status = "completed"
        mock_scan.started_at = "2025-01-01T00:00:00"
        mock_scan.completed_at = "2025-01-01T00:01:00"
        mock_scan.duration_seconds = 60.0
        mock_scan.modules_run = ["domain_profile"]
        mock_scan.findings_count = 3
        mock_scan.risk_score = 45.0
        mock_scan.error = None

        mock_finding = MagicMock()
        mock_finding.severity = "high"
        mock_finding.title = "Test Finding"
        mock_finding.description = "Test description"

        mock_db = MagicMock()
        mock_db.get_scan.return_value = mock_scan
        mock_db.get_findings.return_value = [mock_finding]
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "Test Finding" in captured.out

    def test_history_delete_no_id(self, capsys):
        """Test history delete without ID."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "delete"
        args.id = None
        config = CLIConfig()

        mock_db = MagicMock()
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 1

    def test_history_delete_success(self, capsys):
        """Test history delete success."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "delete"
        args.id = 1
        config = CLIConfig()

        mock_db = MagicMock()
        mock_db.delete_scan.return_value = True
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "deleted" in captured.out

    def test_history_stats(self, capsys):
        """Test history stats."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "stats"
        config = CLIConfig()

        mock_db = MagicMock()
        mock_db.get_stats.return_value = {
            "total_scans": 10,
            "completed_scans": 8,
            "failed_scans": 2,
            "total_findings": 50,
            "findings_by_severity": {"high": 10, "medium": 30, "low": 10},
            "recent_targets": ["example.com", "test.com"],
        }
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total Scans: 10" in captured.out

    def test_history_cleanup(self, capsys):
        """Test history cleanup."""
        from redops.cli.app import cmd_history
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "cleanup"
        args.days = 30
        config = CLIConfig()

        mock_db = MagicMock()
        mock_db.cleanup_old.return_value = 5
        with patch("redops.core.scan_history.get_history_db", return_value=mock_db):
            result = cmd_history(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "Deleted 5" in captured.out


class TestCmdPlugin:
    """Tests for cmd_plugin command."""

    def test_plugin_list_empty(self, capsys):
        """Test plugin list with no plugins."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "list"
        config = CLIConfig(quiet=True)

        mock_registry = MagicMock()
        mock_registry.plugins = {}
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "No plugins installed" in captured.out

    def test_plugin_list_with_plugins(self, capsys):
        """Test plugin list with plugins."""
        from redops.cli.app import cmd_plugin
        from redops.core.plugin_system import PluginState, PluginType
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "list"
        config = CLIConfig(quiet=True)

        mock_metadata = MagicMock()
        mock_metadata.version = "1.0.0"
        mock_metadata.description = "Test plugin"
        mock_metadata.plugin_type = PluginType.MODULE
        mock_metadata.author = "Test"
        mock_metadata.tags = ["test"]

        mock_plugin_info = MagicMock()
        mock_plugin_info.metadata = mock_metadata
        mock_plugin_info.state = PluginState.ACTIVE
        mock_plugin_info.error = None

        mock_registry = MagicMock()
        mock_registry.plugins = {"test_plugin": mock_plugin_info}
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "test_plugin" in captured.out

    def test_plugin_load_no_source(self, capsys):
        """Test plugin load without source."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "load"
        args.source = None
        config = CLIConfig()

        mock_registry = MagicMock()
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "source required" in captured.err

    def test_plugin_load_from_file(self, tmp_path, capsys):
        """Test plugin load from file."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        plugin_file = tmp_path / "plugin.py"
        plugin_file.write_text("# test plugin")

        args = MagicMock()
        args.action = "load"
        args.source = str(plugin_file)
        config = CLIConfig()

        mock_registry = MagicMock()
        mock_registry.register_from_file.return_value = ["test_plugin"]
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "Loaded" in captured.out

    def test_plugin_enable_no_name(self, capsys):
        """Test plugin enable without name."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "enable"
        args.name = None
        config = CLIConfig()

        mock_registry = MagicMock()
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 1

    def test_plugin_enable_success(self, capsys):
        """Test plugin enable success."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "enable"
        args.name = "test_plugin"
        config = CLIConfig()

        mock_registry = MagicMock()
        mock_registry.enable.return_value = True
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "enabled" in captured.out

    def test_plugin_disable_success(self, capsys):
        """Test plugin disable success."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "disable"
        args.name = "test_plugin"
        config = CLIConfig()

        mock_registry = MagicMock()
        mock_registry.disable.return_value = True
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "disabled" in captured.out

    def test_plugin_info_not_found(self, capsys):
        """Test plugin info for non-existent plugin."""
        from redops.cli.app import cmd_plugin
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "info"
        args.name = "nonexistent"
        config = CLIConfig()

        mock_registry = MagicMock()
        mock_registry.get.return_value = None
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_plugin_info_success(self, capsys):
        """Test plugin info success."""
        from redops.cli.app import cmd_plugin
        from redops.core.plugin_system import PluginState, PluginType
        from unittest.mock import patch, MagicMock

        args = MagicMock()
        args.action = "info"
        args.name = "test_plugin"
        config = CLIConfig()

        mock_metadata = MagicMock()
        mock_metadata.name = "test_plugin"
        mock_metadata.version = "1.0.0"
        mock_metadata.description = "A test plugin"
        mock_metadata.plugin_type = PluginType.MODULE
        mock_metadata.author = "Test Author"
        mock_metadata.tags = ["test"]
        mock_metadata.dependencies = []
        mock_metadata.homepage = "https://example.com"
        mock_metadata.license = "MIT"

        mock_plugin_info = MagicMock()
        mock_plugin_info.metadata = mock_metadata
        mock_plugin_info.state = PluginState.ACTIVE
        mock_plugin_info.path = "/path/to/plugin"
        mock_plugin_info.error = None

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin_info
        with patch(
            "redops.core.plugin_system.get_plugin_registry", return_value=mock_registry
        ):
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                result = cmd_plugin(args, config)

        assert result == 0
        captured = capsys.readouterr()
        assert "test_plugin" in captured.out
        assert "1.0.0" in captured.out
