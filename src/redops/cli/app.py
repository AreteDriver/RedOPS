"""
RedOPS CLI Application.

Unified command-line interface for running security assessments,
generating reports, and managing the RedOPS framework.

Commands:
- scan: Run security assessment on a target
- report: Generate reports from previous scans
- modules: List and manage available modules
- config: Manage configuration
- version: Show version information
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from redops.core.context import Context


class OutputFormat(Enum):
    """Output format options."""

    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    TEXT = "text"
    SUMMARY = "summary"


class Verbosity(Enum):
    """Verbosity levels."""

    QUIET = 0
    NORMAL = 1
    VERBOSE = 2
    DEBUG = 3


class ScanPreset(Enum):
    """Scan preset configurations."""

    QUICK = "quick"
    RECON = "recon"
    FULL = "full"
    COMPLIANCE = "compliance"
    INFRASTRUCTURE = "infrastructure"
    THREAT_INTEL = "threat_intel"
    EXECUTIVE = "executive"
    AI_ENHANCED = "ai_enhanced"


@dataclass
class CLIConfig:
    """CLI configuration."""

    verbosity: Verbosity = Verbosity.NORMAL
    output_format: OutputFormat = OutputFormat.TEXT
    output_dir: str = "./output"
    config_file: Optional[str] = None
    no_color: bool = False
    quiet: bool = False
    dry_run: bool = False


@dataclass
class ScanResult:
    """Result of a scan operation."""

    success: bool
    target: str
    preset: str
    modules_run: List[str]
    findings_count: int
    duration_seconds: float
    output_files: List[str]
    errors: List[str]
    context: Optional[Context] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "target": self.target,
            "preset": self.preset,
            "modules_run": self.modules_run,
            "findings_count": self.findings_count,
            "duration_seconds": self.duration_seconds,
            "output_files": self.output_files,
            "errors": self.errors,
        }


# ============================================================================
# Preset Definitions
# ============================================================================

SCAN_PRESETS = {
    ScanPreset.QUICK: {
        "name": "Quick Scan",
        "description": "Fast reconnaissance with essential modules",
        "modules": ["domain_profile", "tech_stack", "exposure_scan"],
        "estimated_time": "1-2 minutes",
    },
    ScanPreset.RECON: {
        "name": "Reconnaissance",
        "description": "Comprehensive reconnaissance and discovery",
        "modules": [
            "domain_profile",
            "tech_stack",
            "social_osint",
            "exposure_scan",
            "infrastructure",
        ],
        "estimated_time": "5-10 minutes",
    },
    ScanPreset.FULL: {
        "name": "Full Assessment",
        "description": "Complete security assessment with all modules",
        "modules": [
            "domain_profile",
            "tech_stack",
            "social_osint",
            "exposure_scan",
            "infrastructure",
            "threat_intel",
            "compliance",
            "correlation",
            "executive_report",
        ],
        "estimated_time": "15-30 minutes",
    },
    ScanPreset.COMPLIANCE: {
        "name": "Compliance Check",
        "description": "Compliance-focused assessment",
        "modules": [
            "domain_profile",
            "exposure_scan",
            "compliance",
            "executive_report",
        ],
        "estimated_time": "5-10 minutes",
    },
    ScanPreset.INFRASTRUCTURE: {
        "name": "Infrastructure Analysis",
        "description": "Cloud and infrastructure focused",
        "modules": [
            "domain_profile",
            "tech_stack",
            "infrastructure",
            "exposure_scan",
        ],
        "estimated_time": "3-5 minutes",
    },
    ScanPreset.THREAT_INTEL: {
        "name": "Threat Intelligence",
        "description": "Threat indicator analysis",
        "modules": [
            "domain_profile",
            "threat_intel",
            "exposure_scan",
            "correlation",
        ],
        "estimated_time": "5-10 minutes",
    },
    ScanPreset.EXECUTIVE: {
        "name": "Executive Report",
        "description": "Generate executive-ready report",
        "modules": [
            "domain_profile",
            "exposure_scan",
            "compliance",
            "correlation",
            "executive_report",
        ],
        "estimated_time": "10-15 minutes",
    },
    ScanPreset.AI_ENHANCED: {
        "name": "AI-Enhanced Assessment",
        "description": "Full assessment with AI-powered analysis (requires API key)",
        "modules": [
            "domain_profile",
            "tech_stack",
            "exposure_scan",
            "infrastructure",
            "threat_intel",
            "compliance",
            "correlation",
            "ai_analyze",
            "ai_recommend",
            "executive_report",
        ],
        "estimated_time": "20-30 minutes",
    },
}

# Available modules
AVAILABLE_MODULES = {
    "domain_profile": {
        "name": "Domain Profile",
        "description": "DNS, WHOIS, and domain intelligence",
        "category": "recon",
    },
    "tech_stack": {
        "name": "Technology Stack",
        "description": "Detect web technologies and frameworks",
        "category": "recon",
    },
    "social_osint": {
        "name": "Social OSINT",
        "description": "Social media and employee discovery",
        "category": "recon",
    },
    "exposure_scan": {
        "name": "Exposure Scanner",
        "description": "Identify exposed services and data",
        "category": "recon",
    },
    "infrastructure": {
        "name": "Infrastructure Analysis",
        "description": "Cloud provider and CDN detection",
        "category": "recon",
    },
    "threat_intel": {
        "name": "Threat Intelligence",
        "description": "IOC analysis and threat correlation",
        "category": "intel",
    },
    "compliance": {
        "name": "Compliance Mapping",
        "description": "Map findings to compliance frameworks",
        "category": "compliance",
    },
    "correlation": {
        "name": "Correlation Engine",
        "description": "Correlate findings across modules",
        "category": "analysis",
    },
    "executive_report": {
        "name": "Executive Report",
        "description": "Generate stakeholder-ready reports",
        "category": "reporting",
    },
    "risk_scoring": {
        "name": "Risk Scoring",
        "description": "Calculate risk scores for findings",
        "category": "analysis",
    },
    "ai_analyze": {
        "name": "AI Analysis",
        "description": "AI-powered analysis of findings (requires API key)",
        "category": "ai",
    },
    "ai_summarize": {
        "name": "AI Summary",
        "description": "AI-generated executive summary (requires API key)",
        "category": "ai",
    },
    "ai_recommend": {
        "name": "AI Recommendations",
        "description": "AI-generated remediation suggestions (requires API key)",
        "category": "ai",
    },
}


# ============================================================================
# CLI Commands
# ============================================================================


def cmd_scan(args: argparse.Namespace, config: CLIConfig) -> int:
    """Execute a security scan."""
    target = args.target
    preset = ScanPreset(args.preset) if args.preset else ScanPreset.QUICK
    modules = args.modules.split(",") if args.modules else None

    if not config.quiet:
        print_header("RedOPS Security Scanner")
        print(f"Target: {target}")
        print(f"Preset: {preset.value}")
        if modules:
            print(f"Modules: {', '.join(modules)}")
        print()

    # Get modules to run
    if modules:
        modules_to_run = [m.strip() for m in modules if m.strip() in AVAILABLE_MODULES]
    else:
        modules_to_run = SCAN_PRESETS[preset]["modules"]

    if not modules_to_run:
        print_error("No valid modules specified")
        return 1

    if not config.quiet:
        print(f"Running {len(modules_to_run)} modules...")
        print()

    # Dry run check
    if config.dry_run:
        print_info("DRY RUN - No actual scan will be performed")
        print()
        print("Would run modules:")
        for mod in modules_to_run:
            mod_info = AVAILABLE_MODULES.get(mod, {})
            print(f"  - {mod}: {mod_info.get('description', 'Unknown')}")
        return 0

    # Execute scan
    start_time = datetime.now()
    result = execute_scan(target, modules_to_run, config)
    duration = (datetime.now() - start_time).total_seconds()

    result.duration_seconds = duration

    # Output results
    if config.output_format == OutputFormat.JSON:
        print(json.dumps(result.to_dict(), indent=2))
    elif config.output_format == OutputFormat.SUMMARY:
        print_scan_summary(result)
    else:
        print_scan_results(result, config)

    return 0 if result.success else 1


def cmd_report(args: argparse.Namespace, config: CLIConfig) -> int:
    """Generate a report from scan data."""
    input_file = args.input
    report_type = args.type
    output_file = args.output

    if not config.quiet:
        print_header("RedOPS Report Generator")
        print(f"Input: {input_file}")
        print(f"Type: {report_type}")
        print(f"Output: {output_file or 'stdout'}")
        print()

    # Load scan data
    try:
        with open(input_file, "r") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        print_error(f"Input file not found: {input_file}")
        return 1
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON in input file: {e}")
        return 1

    # Generate report
    report = generate_report(scan_data, report_type, config)

    # Output
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            f.write(report)
        print_success(f"Report saved to: {output_file}")
    else:
        print(report)

    return 0


def cmd_modules(args: argparse.Namespace, config: CLIConfig) -> int:
    """List available modules."""
    if not config.quiet:
        print_header("Available Modules")
        print()

    # Group by category
    categories: Dict[str, List[str]] = {}
    for mod_id, mod_info in AVAILABLE_MODULES.items():
        cat = mod_info.get("category", "other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(mod_id)

    if config.output_format == OutputFormat.JSON:
        print(json.dumps(AVAILABLE_MODULES, indent=2))
    else:
        for category, module_ids in sorted(categories.items()):
            print(f"{category.upper()}:")
            for mod_id in module_ids:
                mod_info = AVAILABLE_MODULES[mod_id]
                print(f"  {mod_id}")
                print(f"    {mod_info.get('description', '')}")
            print()

    return 0


def cmd_presets(args: argparse.Namespace, config: CLIConfig) -> int:
    """List available scan presets."""
    if not config.quiet:
        print_header("Scan Presets")
        print()

    if config.output_format == OutputFormat.JSON:
        output = {
            p.value: {
                "name": info["name"],
                "description": info["description"],
                "modules": info["modules"],
                "estimated_time": info["estimated_time"],
            }
            for p, info in SCAN_PRESETS.items()
        }
        print(json.dumps(output, indent=2))
    else:
        for preset, info in SCAN_PRESETS.items():
            print(f"{preset.value}")
            print(f"  Name: {info['name']}")
            print(f"  Description: {info['description']}")
            print(f"  Modules: {', '.join(info['modules'])}")
            print(f"  Estimated time: {info['estimated_time']}")
            print()

    return 0


def cmd_config(args: argparse.Namespace, config: CLIConfig) -> int:
    """Manage configuration."""
    action = args.action

    if action == "show":
        config_path = get_config_path()
        if config_path.exists():
            print(config_path.read_text())
        else:
            print_info(f"No config file found at: {config_path}")
            print("Using default configuration.")

    elif action == "init":
        config_path = get_config_path()
        if config_path.exists() and not args.force:
            print_error(f"Config already exists: {config_path}")
            print("Use --force to overwrite")
            return 1

        default_config = get_default_config()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(default_config, indent=2))
        print_success(f"Config initialized at: {config_path}")

    elif action == "path":
        print(get_config_path())

    return 0


def cmd_settings(args: argparse.Namespace, config: CLIConfig) -> int:
    """Open interactive settings menu."""
    from redops.cli.settings import run_settings_menu

    return run_settings_menu(quiet=config.quiet)


def cmd_apikey(args: argparse.Namespace, config: CLIConfig) -> int:
    """Manage API keys."""
    from redops.cli.settings import (
        set_api_key_direct,
        get_api_key_direct,
        list_api_keys,
        API_PROVIDERS,
        mask_key,
    )

    action = args.action

    if action == "list":
        list_api_keys()

    elif action == "set":
        provider = args.provider
        if not provider:
            print_error("Provider is required. Use --provider <name>")
            print(f"Available providers: {', '.join(API_PROVIDERS.keys())}")
            return 1

        if args.key:
            key = args.key
        else:
            # Prompt for key securely
            import getpass

            key = getpass.getpass(f"Enter API key for {provider}: ")

        if not key:
            print_error("API key cannot be empty")
            return 1

        if set_api_key_direct(provider, key):
            return 0
        return 1

    elif action == "get":
        provider = args.provider
        if not provider:
            print_error("Provider is required. Use --provider <name>")
            return 1

        key = get_api_key_direct(provider)
        if key:
            if args.show:
                print(key)
            else:
                print(f"{provider}: {mask_key(key)}")
        else:
            print(f"{provider}: (not set)")

    elif action == "remove":
        provider = args.provider
        if not provider:
            print_error("Provider is required. Use --provider <name>")
            return 1

        set_api_key_direct(provider, None)
        print_success(f"API key for {provider} removed.")

    return 0


def cmd_ai(args: argparse.Namespace, config: CLIConfig) -> int:
    """AI-assisted analysis commands."""
    from redops.modules.ai_assistant import AIAssistant

    action = args.action
    provider = getattr(args, "provider", None)
    model = getattr(args, "model", None)

    # Initialize AI assistant
    try:
        assistant = AIAssistant(provider=provider, model=model)
    except Exception as e:
        print_error(f"Failed to initialize AI assistant: {e}")
        print_info(
            "Make sure you have configured an API key using 'redops settings' or 'redops apikey set'"
        )
        return 1

    if action == "analyze":
        # Analyze scan results
        input_file = args.input
        if not input_file:
            print_error("Input file required. Use --input <file>")
            return 1

        try:
            with open(input_file, "r") as f:
                scan_data = json.load(f)
        except Exception as e:
            print_error(f"Failed to read input file: {e}")
            return 1

        if not config.quiet:
            print_info("Analyzing scan results with AI...")

        result = assistant.analyze_findings(scan_data)
        print(result)

    elif action == "explain":
        # Explain a finding or concept
        query = args.query
        if not query:
            print_error("Query required. Use --query <text>")
            return 1

        context_file = args.context
        context_data = None
        if context_file:
            try:
                with open(context_file, "r") as f:
                    context_data = json.load(f)
            except Exception:
                pass

        if not config.quiet:
            print_info("Getting AI explanation...")

        result = assistant.explain(query, context=context_data)
        print(result)

    elif action == "suggest":
        # Get remediation suggestions
        input_file = args.input
        if not input_file:
            print_error("Input file required. Use --input <file>")
            return 1

        try:
            with open(input_file, "r") as f:
                scan_data = json.load(f)
        except Exception as e:
            print_error(f"Failed to read input file: {e}")
            return 1

        if not config.quiet:
            print_info("Generating remediation suggestions...")

        result = assistant.suggest_remediations(scan_data)
        print(result)

    elif action == "summarize":
        # Summarize scan results
        input_file = args.input
        if not input_file:
            print_error("Input file required. Use --input <file>")
            return 1

        try:
            with open(input_file, "r") as f:
                scan_data = json.load(f)
        except Exception as e:
            print_error(f"Failed to read input file: {e}")
            return 1

        if not config.quiet:
            print_info("Generating AI summary...")

        result = assistant.summarize(scan_data)
        print(result)

    elif action == "chat":
        # Interactive chat mode
        if not config.quiet:
            print_header("AI Assistant Chat")
            print("Type 'exit' or 'quit' to end the session.")
            print("Type 'load <file>' to load scan data for context.")
            print()

        context_data = None
        while True:
            try:
                user_input = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting chat.")
                break

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit"):
                print("Goodbye!")
                break

            if user_input.lower().startswith("load "):
                filepath = user_input[5:].strip()
                try:
                    with open(filepath, "r") as f:
                        context_data = json.load(f)
                    print(f"Loaded context from: {filepath}")
                except Exception as e:
                    print(f"Error loading file: {e}")
                continue

            response = assistant.chat(user_input, context=context_data)
            print(f"\nAssistant: {response}\n")

    return 0


def cmd_version(args: argparse.Namespace, config: CLIConfig) -> int:
    """Show version information."""
    from redops.main import __version__

    if config.output_format == OutputFormat.JSON:
        print(
            json.dumps(
                {
                    "name": "RedOPS",
                    "version": __version__,
                    "python": sys.version.split()[0],
                }
            )
        )
    else:
        print(f"RedOPS version {__version__}")
        print(f"Python {sys.version.split()[0]}")

    return 0


# ============================================================================
# Execution Functions
# ============================================================================


def execute_scan(target: str, modules: List[str], config: CLIConfig) -> ScanResult:
    """Execute a scan with specified modules."""
    errors = []
    modules_run = []
    findings_count = 0
    output_files = []

    try:
        # Create context
        ctx = Context(target=target)

        # Run each module
        for module_name in modules:
            if not config.quiet:
                print_progress(f"Running {module_name}...")

            try:
                ctx = run_module(ctx, module_name, config)
                modules_run.append(module_name)
            except Exception as e:
                errors.append(f"{module_name}: {str(e)}")
                if config.verbosity == Verbosity.DEBUG:
                    import traceback

                    traceback.print_exc()

        # Count findings
        findings_count = count_findings(ctx)

        # Save output
        if config.output_dir:
            output_files = save_scan_output(ctx, config)

        return ScanResult(
            success=len(errors) == 0,
            target=target,
            preset="custom",
            modules_run=modules_run,
            findings_count=findings_count,
            duration_seconds=0,  # Set by caller
            output_files=output_files,
            errors=errors,
            context=ctx,
        )

    except Exception as e:
        return ScanResult(
            success=False,
            target=target,
            preset="custom",
            modules_run=modules_run,
            findings_count=0,
            duration_seconds=0,
            output_files=[],
            errors=[str(e)],
        )


def run_module(ctx: Context, module_name: str, config: CLIConfig) -> Context:
    """Run a specific module."""
    # Import and run the appropriate module
    module_runners = {
        "domain_profile": run_domain_profile,
        "tech_stack": run_tech_stack,
        "exposure_scan": run_exposure_scan,
        "infrastructure": run_infrastructure,
        "threat_intel": run_threat_intel,
        "compliance": run_compliance,
        "correlation": run_correlation,
        "executive_report": run_executive_report,
        "social_osint": run_social_osint,
        "risk_scoring": run_risk_scoring,
        "ai_analyze": run_ai_analyze,
        "ai_summarize": run_ai_summarize,
        "ai_recommend": run_ai_recommend,
    }

    runner = module_runners.get(module_name)
    if runner:
        return runner(ctx, config)
    else:
        ctx.log(f"Unknown module: {module_name}", level="WARNING")
        return ctx


def run_domain_profile(ctx: Context, config: CLIConfig) -> Context:
    """Run domain profile module."""
    from redops.modules.recon.domains import analyze_domain

    return analyze_domain(ctx, {})


def run_tech_stack(ctx: Context, config: CLIConfig) -> Context:
    """Run tech stack module."""
    from redops.modules.recon.tech_stack import detect_technologies

    return detect_technologies(ctx, {})


def run_exposure_scan(ctx: Context, config: CLIConfig) -> Context:
    """Run exposure scan module."""
    from redops.modules.recon.exposure_scan import scan_exposures

    return scan_exposures(ctx, {})


def run_infrastructure(ctx: Context, config: CLIConfig) -> Context:
    """Run infrastructure analysis module."""
    from redops.modules.recon.infrastructure import analyze_infrastructure

    return analyze_infrastructure(ctx, {})


def run_threat_intel(ctx: Context, config: CLIConfig) -> Context:
    """Run threat intel module."""
    from redops.modules.intel.threat_intel import analyze_threat_intel

    return analyze_threat_intel(ctx, {})


def run_compliance(ctx: Context, config: CLIConfig) -> Context:
    """Run compliance module."""
    from redops.modules.compliance.compliance_map import assess_compliance

    return assess_compliance(ctx, {})


def run_correlation(ctx: Context, config: CLIConfig) -> Context:
    """Run correlation engine."""
    from redops.modules.analysis.correlation_engine import correlate_findings

    return correlate_findings(ctx, {})


def run_executive_report(ctx: Context, config: CLIConfig) -> Context:
    """Run executive report module."""
    from redops.modules.reporting.executive_report import generate_executive_report

    return generate_executive_report(ctx, {})


def run_social_osint(ctx: Context, config: CLIConfig) -> Context:
    """Run social OSINT module."""
    from redops.modules.recon.social_osint import gather_social_intel

    return gather_social_intel(ctx, {})


def run_risk_scoring(ctx: Context, config: CLIConfig) -> Context:
    """Run risk scoring module."""
    from redops.modules.corp_assessment.risk_scoring import score_risks

    return score_risks(ctx, {})


def run_ai_analyze(ctx: Context, config: CLIConfig) -> Context:
    """Run AI analysis module."""
    from redops.modules.ai_assistant import ai_analyze

    return ai_analyze(ctx, {})


def run_ai_summarize(ctx: Context, config: CLIConfig) -> Context:
    """Run AI summarization module."""
    from redops.modules.ai_assistant import ai_summarize

    return ai_summarize(ctx, {})


def run_ai_recommend(ctx: Context, config: CLIConfig) -> Context:
    """Run AI recommendations module."""
    from redops.modules.ai_assistant import ai_recommend

    return ai_recommend(ctx, {})


def count_findings(ctx: Context) -> int:
    """Count total findings in context."""
    count = 0

    # From correlations
    correlations = ctx.get("correlations", {})
    count += len(correlations.get("findings", []))

    # From exposure scan
    exposure = ctx.get("exposure_scan", {})
    count += len(exposure.get("exposures", []))

    # From threat intel
    threat_intel = ctx.get("threat_intel", {})
    count += len(threat_intel.get("iocs", []))

    # From compliance
    compliance = ctx.get("compliance", {})
    count += len(compliance.get("gaps", []))

    return count


def save_scan_output(ctx: Context, config: CLIConfig) -> List[str]:
    """Save scan output to files."""
    output_files = []
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = (
        ctx.target.replace(".", "_").replace("/", "_") if ctx.target else "unknown"
    )

    # Save JSON data
    json_file = output_dir / f"scan_{target_safe}_{timestamp}.json"
    with open(json_file, "w") as f:
        json.dump(ctx.data, f, indent=2, default=str)
    output_files.append(str(json_file))

    # Save executive report if available
    exec_report = ctx.get("executive_report", {})
    if exec_report:
        report_file = output_dir / f"report_{target_safe}_{timestamp}.json"
        with open(report_file, "w") as f:
            json.dump(exec_report, f, indent=2, default=str)
        output_files.append(str(report_file))

    return output_files


def generate_report(
    scan_data: Dict[str, Any], report_type: str, config: CLIConfig
) -> str:
    """Generate a report from scan data."""
    if report_type == "executive":
        return generate_executive_text_report(scan_data)
    elif report_type == "technical":
        return generate_technical_report(scan_data)
    elif report_type == "json":
        return json.dumps(scan_data, indent=2, default=str)
    elif report_type == "summary":
        return generate_summary_report(scan_data)
    else:
        return json.dumps(scan_data, indent=2, default=str)


def generate_executive_text_report(data: Dict[str, Any]) -> str:
    """Generate executive text report."""
    lines = ["=" * 60, "EXECUTIVE SECURITY ASSESSMENT REPORT", "=" * 60, ""]

    exec_report = data.get("executive_report", {})
    summary = exec_report.get("executive_summary", {})

    lines.append(f"Target: {summary.get('target', 'Unknown')}")
    lines.append(f"Generated: {summary.get('generated_at', 'Unknown')}")
    lines.append(f"Risk Level: {summary.get('overall_risk_level', 'Unknown').upper()}")
    lines.append(f"Risk Score: {summary.get('risk_score', 0)}/100")
    lines.append("")

    lines.append("EXECUTIVE BRIEF")
    lines.append("-" * 40)
    lines.append(summary.get("executive_brief", "No brief available"))
    lines.append("")

    lines.append("KEY FINDINGS")
    lines.append("-" * 40)
    for finding in summary.get("key_findings", [])[:5]:
        lines.append(
            f"  [{finding.get('severity', '').upper()}] {finding.get('title', '')}"
        )

    lines.append("")
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 40)
    for rec in exec_report.get("recommendations", [])[:5]:
        lines.append(f"  [{rec.get('priority', '').upper()}] {rec.get('title', '')}")

    return "\n".join(lines)


def generate_technical_report(data: Dict[str, Any]) -> str:
    """Generate technical report."""
    return json.dumps(data, indent=2, default=str)


def generate_summary_report(data: Dict[str, Any]) -> str:
    """Generate summary report."""
    lines = ["SCAN SUMMARY", "=" * 40, ""]

    # Count findings from various sources
    exposure = data.get("exposure_scan", {})
    threat_intel = data.get("threat_intel", {})
    compliance = data.get("compliance", {})
    correlations = data.get("correlations", {})

    lines.append(f"Exposures: {len(exposure.get('exposures', []))}")
    lines.append(f"Threat Indicators: {len(threat_intel.get('iocs', []))}")
    lines.append(f"Compliance Gaps: {len(compliance.get('gaps', []))}")
    lines.append(f"Correlations: {len(correlations.get('correlations', []))}")
    lines.append(f"Insights: {len(correlations.get('insights', []))}")

    return "\n".join(lines)


# ============================================================================
# Helper Functions
# ============================================================================


def get_config_path() -> Path:
    """Get the configuration file path."""
    # Check environment variable first
    import os

    env_path = os.environ.get("REDOPS_CONFIG")
    if env_path:
        return Path(env_path)

    # Default to user config directory
    home = Path.home()
    return home / ".config" / "redops" / "config.json"


def get_default_config() -> Dict[str, Any]:
    """Get default configuration."""
    return {
        "output_dir": "./output",
        "verbosity": "normal",
        "output_format": "text",
        "modules": {
            "enabled": list(AVAILABLE_MODULES.keys()),
        },
        "api_keys": {
            "openai": None,
            "anthropic": None,
            "shodan": None,
            "virustotal": None,
            "securitytrails": None,
            "censys": None,
            "hunter": None,
        },
        "ai": {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "max_tokens": 2048,
            "temperature": 0.7,
            "enabled": True,
        },
    }


# ============================================================================
# Output Formatting
# ============================================================================


def print_header(title: str):
    """Print a header."""
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)
    print()


def print_error(message: str):
    """Print an error message."""
    print(f"ERROR: {message}", file=sys.stderr)


def print_warning(message: str):
    """Print a warning message."""
    print(f"WARNING: {message}")


def print_info(message: str):
    """Print an info message."""
    print(f"INFO: {message}")


def print_success(message: str):
    """Print a success message."""
    print(f"SUCCESS: {message}")


def print_progress(message: str):
    """Print a progress message."""
    print(f"  -> {message}")


def print_scan_summary(result: ScanResult):
    """Print scan summary."""
    status = "SUCCESS" if result.success else "FAILED"
    print(f"\n{status}: Scan completed")
    print(f"  Target: {result.target}")
    print(f"  Modules: {len(result.modules_run)}")
    print(f"  Findings: {result.findings_count}")
    print(f"  Duration: {result.duration_seconds:.1f}s")


def print_scan_results(result: ScanResult, config: CLIConfig):
    """Print detailed scan results."""
    print()
    print("=" * 60)
    print("  SCAN RESULTS")
    print("=" * 60)
    print()

    print(f"Status: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Target: {result.target}")
    print(f"Duration: {result.duration_seconds:.1f} seconds")
    print()

    print("Modules Executed:")
    for mod in result.modules_run:
        print(f"  - {mod}")
    print()

    print(f"Total Findings: {result.findings_count}")
    print()

    if result.output_files:
        print("Output Files:")
        for f in result.output_files:
            print(f"  - {f}")
        print()

    if result.errors:
        print("Errors:")
        for err in result.errors:
            print(f"  - {err}")
        print()


# ============================================================================
# Main Entry Point
# ============================================================================


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="redops",
        description="RedOPS - Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  redops scan example.com                    # Quick scan
  redops scan example.com --preset full      # Full assessment
  redops scan example.com -m infrastructure,compliance
  redops report scan_output.json -t executive
  redops modules                             # List modules
  redops presets                             # List presets
  redops settings                            # Open settings menu
  redops apikey set -p openai                # Set OpenAI API key
  redops apikey list                         # List configured API keys
  redops ai analyze -i scan.json             # AI analysis of scan
  redops ai chat                             # Interactive AI chat
  redops ai explain -q "What is XSS?"        # AI explanation
        """,
    )

    # Global options
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be repeated)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress output except errors"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="./output",
        help="Output directory (default: ./output)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "html", "markdown", "text", "summary"],
        default="text",
        help="Output format",
    )
    parser.add_argument("--config", "-c", help="Config file path")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Target to scan (domain, IP, etc.)")
    scan_parser.add_argument(
        "-p",
        "--preset",
        choices=[p.value for p in ScanPreset],
        default="quick",
        help="Scan preset",
    )
    scan_parser.add_argument(
        "-m", "--modules", help="Comma-separated list of modules to run"
    )

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report")
    report_parser.add_argument("input", help="Input scan JSON file")
    report_parser.add_argument(
        "-t",
        "--type",
        choices=["executive", "technical", "summary", "json"],
        default="summary",
        help="Report type",
    )
    report_parser.add_argument("--output", help="Output file (default: stdout)")

    # Modules command
    subparsers.add_parser("modules", help="List available modules")

    # Presets command
    subparsers.add_parser("presets", help="List scan presets")

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument(
        "action", choices=["show", "init", "path"], help="Config action"
    )
    config_parser.add_argument(
        "--force", action="store_true", help="Force overwrite existing config"
    )

    # Settings command (interactive menu)
    subparsers.add_parser("settings", help="Open interactive settings menu")

    # API Key management command
    apikey_parser = subparsers.add_parser("apikey", help="Manage API keys")
    apikey_parser.add_argument(
        "action", choices=["list", "set", "get", "remove"], help="API key action"
    )
    apikey_parser.add_argument(
        "--provider", "-p", help="API provider name (openai, anthropic, shodan, etc.)"
    )
    apikey_parser.add_argument(
        "--key", "-k", help="API key value (will prompt securely if not provided)"
    )
    apikey_parser.add_argument(
        "--show", "-s", action="store_true", help="Show full API key (use with caution)"
    )

    # AI Assistant command
    ai_parser = subparsers.add_parser("ai", help="AI-assisted analysis")
    ai_parser.add_argument(
        "action",
        choices=["analyze", "explain", "suggest", "summarize", "chat"],
        help="AI action",
    )
    ai_parser.add_argument("--input", "-i", help="Input scan results file (JSON)")
    ai_parser.add_argument("--query", "-q", help="Query or question for AI")
    ai_parser.add_argument("--context", "-x", help="Additional context file (JSON)")
    ai_parser.add_argument(
        "--provider",
        "-p",
        choices=["openai", "anthropic"],
        help="AI provider (default: from config)",
    )
    ai_parser.add_argument(
        "--model",
        "-m",
        help="Model name (default: from config)",
    )

    # Version command
    subparsers.add_parser("version", help="Show version")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    # Build config
    verbosity = (
        Verbosity.QUIET if parsed.quiet else Verbosity(min(parsed.verbose + 1, 3))
    )
    config = CLIConfig(
        verbosity=verbosity,
        output_format=OutputFormat(parsed.format),
        output_dir=parsed.output_dir,
        config_file=parsed.config,
        no_color=parsed.no_color,
        quiet=parsed.quiet,
        dry_run=parsed.dry_run,
    )

    # Dispatch command
    commands = {
        "scan": cmd_scan,
        "report": cmd_report,
        "modules": cmd_modules,
        "presets": cmd_presets,
        "config": cmd_config,
        "settings": cmd_settings,
        "apikey": cmd_apikey,
        "ai": cmd_ai,
        "version": cmd_version,
    }

    if parsed.command in commands:
        return commands[parsed.command](parsed, config)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
