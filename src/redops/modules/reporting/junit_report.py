"""
JUnit XML report generation.

Exports findings in JUnit XML format for CI/CD pipeline integration.
This format is widely supported by Jenkins, GitLab CI, CircleCI, etc.
"""

from typing import Any
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom
from redops.core.context import Context


def export_junit(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export findings as a JUnit XML report.

    JUnit format treats findings as test cases, with failed tests
    representing security issues found. This enables CI/CD
    pipeline integration and fail-on-finding workflows.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - output_dir: Directory for output (default: ./output)
            - output_name: Output filename (auto-generated if not specified)
            - suite_name: Test suite name (default: RedOps Security Assessment)
            - fail_on_critical: Treat critical findings as failures (default: True)
            - fail_on_high: Treat high findings as failures (default: True)
            - fail_on_medium: Treat medium findings as failures (default: False)

    Returns:
        Updated context with junit_export_path
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    suite_name = params.get("suite_name", "RedOps Security Assessment")
    fail_on_critical = params.get("fail_on_critical", True)
    fail_on_high = params.get("fail_on_high", True)
    fail_on_medium = params.get("fail_on_medium", False)

    ctx.log("Generating JUnit XML report", level="INFO")

    # Collect findings
    findings = collect_findings(ctx)

    # Build JUnit XML
    xml_doc = create_junit_document(
        ctx,
        findings,
        suite_name=suite_name,
        fail_on_critical=fail_on_critical,
        fail_on_high=fail_on_high,
        fail_on_medium=fail_on_medium,
    )

    # Determine output path
    output_name = params.get(
        "output_name", f"redops_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    )
    output_path = output_dir / output_name

    # Write XML file
    with open(output_path, "w") as f:
        f.write(xml_doc)

    # Calculate stats
    stats = calculate_stats(findings, fail_on_critical, fail_on_high, fail_on_medium)

    ctx.add("junit_export_path", str(output_path))
    ctx.add("junit_tests_count", stats["tests"])
    ctx.add("junit_failures_count", stats["failures"])
    ctx.add("junit_errors_count", stats["errors"])
    ctx.add("junit_skipped_count", stats["skipped"])

    ctx.log(
        f"JUnit report saved to {output_path} "
        f"({stats['tests']} tests, {stats['failures']} failures)",
        level="INFO",
    )

    return ctx


def collect_findings(ctx: Context) -> list[dict[str, Any]]:
    """
    Collect all findings from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of finding dictionaries
    """
    findings = []

    # Get findings stored with finding_ prefix
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            findings.append(value)

    # Get risks if present
    risks = ctx.get("risks", [])
    for risk in risks:
        if isinstance(risk, dict):
            findings.append(
                {
                    "module": risk.get("module", "risk"),
                    "title": risk.get("title", "Unknown Risk"),
                    "description": risk.get("description", ""),
                    "severity": risk.get("level", "medium"),
                    "data": risk.get("data", {}),
                }
            )

    return findings


def create_junit_document(
    ctx: Context,
    findings: list[dict[str, Any]],
    suite_name: str = "RedOps Security Assessment",
    fail_on_critical: bool = True,
    fail_on_high: bool = True,
    fail_on_medium: bool = False,
) -> str:
    """
    Create a JUnit XML document from findings.

    Args:
        ctx: Pipeline context
        findings: List of findings
        suite_name: Test suite name
        fail_on_critical: Treat critical as failure
        fail_on_high: Treat high as failure
        fail_on_medium: Treat medium as failure

    Returns:
        JUnit XML string
    """
    # Create root element
    testsuites = ET.Element("testsuites")

    # Calculate stats
    stats = calculate_stats(findings, fail_on_critical, fail_on_high, fail_on_medium)

    # Add attributes to testsuites
    testsuites.set("name", suite_name)
    testsuites.set("tests", str(stats["tests"]))
    testsuites.set("failures", str(stats["failures"]))
    testsuites.set("errors", str(stats["errors"]))
    testsuites.set("skipped", str(stats["skipped"]))
    testsuites.set("time", str(stats["time"]))
    testsuites.set("timestamp", datetime.now().isoformat())

    # Group findings by module
    modules = group_by_module(findings)

    # Create a testsuite for each module
    for module_name, module_findings in modules.items():
        testsuite = create_testsuite(
            module_name,
            module_findings,
            ctx.target or "target",
            fail_on_critical,
            fail_on_high,
            fail_on_medium,
        )
        testsuites.append(testsuite)

    # If no findings, add a passing test
    if not findings:
        testsuite = ET.SubElement(testsuites, "testsuite")
        testsuite.set("name", "security-checks")
        testsuite.set("tests", "1")
        testsuite.set("failures", "0")
        testsuite.set("errors", "0")
        testsuite.set("skipped", "0")
        testsuite.set("time", "0.001")

        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", "No security issues found")
        testcase.set("classname", "security-checks")
        testcase.set("time", "0.001")

    # Pretty print
    xml_str = ET.tostring(testsuites, encoding="unicode")
    return prettify_xml(xml_str)


def group_by_module(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group findings by module."""
    modules: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        module = finding.get("module", "unknown")
        if module not in modules:
            modules[module] = []
        modules[module].append(finding)

    return modules


def create_testsuite(
    module_name: str,
    findings: list[dict[str, Any]],
    target: str,
    fail_on_critical: bool,
    fail_on_high: bool,
    fail_on_medium: bool,
) -> ET.Element:
    """
    Create a testsuite element for a module.

    Args:
        module_name: Name of the module
        findings: Findings for this module
        target: Assessment target
        fail_on_critical: Treat critical as failure
        fail_on_high: Treat high as failure
        fail_on_medium: Treat medium as failure

    Returns:
        testsuite XML element
    """
    testsuite = ET.Element("testsuite")
    testsuite.set("name", module_name)
    testsuite.set("hostname", target)
    testsuite.set("timestamp", datetime.now().isoformat())

    failures = 0
    errors = 0
    skipped = 0

    for finding in findings:
        testcase = create_testcase(
            finding,
            module_name,
            fail_on_critical,
            fail_on_high,
            fail_on_medium,
        )

        # Count result types
        if testcase.find("failure") is not None:
            failures += 1
        elif testcase.find("error") is not None:
            errors += 1
        elif testcase.find("skipped") is not None:
            skipped += 1

        testsuite.append(testcase)

    testsuite.set("tests", str(len(findings)))
    testsuite.set("failures", str(failures))
    testsuite.set("errors", str(errors))
    testsuite.set("skipped", str(skipped))
    testsuite.set("time", str(len(findings) * 0.001))

    return testsuite


def create_testcase(
    finding: dict[str, Any],
    module_name: str,
    fail_on_critical: bool,
    fail_on_high: bool,
    fail_on_medium: bool,
) -> ET.Element:
    """
    Create a testcase element for a finding.

    Args:
        finding: Finding dictionary
        module_name: Module name for classname
        fail_on_critical: Treat critical as failure
        fail_on_high: Treat high as failure
        fail_on_medium: Treat medium as failure

    Returns:
        testcase XML element
    """
    title = finding.get("title", "Unknown Finding")
    description = finding.get("description", "")
    severity = normalize_severity(finding.get("severity", "medium"))
    data = finding.get("data", {})

    testcase = ET.Element("testcase")
    testcase.set("name", title)
    testcase.set("classname", module_name.replace(".", "-"))
    testcase.set("time", "0.001")

    # Determine if this should be a failure based on severity
    is_failure = (
        (severity == "critical" and fail_on_critical)
        or (severity == "high" and fail_on_high)
        or (severity == "medium" and fail_on_medium)
    )

    if is_failure:
        failure = ET.SubElement(testcase, "failure")
        failure.set("message", title)
        failure.set("type", f"SecurityFinding-{severity.upper()}")
        failure.text = build_failure_text(finding)
    elif severity in ("low", "info", "informational"):
        # Low/info findings are skipped (not failures)
        skipped = ET.SubElement(testcase, "skipped")
        skipped.set("message", f"{severity.upper()}: {title}")

    # Add system-out with details
    if description or data:
        system_out = ET.SubElement(testcase, "system-out")
        system_out.text = build_system_out(finding)

    return testcase


def build_failure_text(finding: dict[str, Any]) -> str:
    """Build failure text from finding."""
    lines = []
    lines.append(f"Title: {finding.get('title', 'Unknown')}")
    lines.append(
        f"Severity: {normalize_severity(finding.get('severity', 'unknown')).upper()}"
    )
    lines.append(f"Module: {finding.get('module', 'unknown')}")
    lines.append("")
    lines.append(f"Description: {finding.get('description', 'No description')}")

    data = finding.get("data", {})
    if data:
        lines.append("")
        lines.append("Additional Data:")
        for key, value in data.items():
            if isinstance(value, (list, dict)):
                lines.append(f"  {key}: {len(value)} items")
            else:
                lines.append(f"  {key}: {value}")

    return "\n".join(lines)


def build_system_out(finding: dict[str, Any]) -> str:
    """Build system-out content from finding."""
    lines = []

    description = finding.get("description", "")
    if description:
        lines.append(description)
        lines.append("")

    data = finding.get("data", {})
    for key, value in data.items():
        if isinstance(value, list):
            lines.append(f"{key}:")
            for item in value[:10]:  # Limit to 10 items
                lines.append(f"  - {item}")
            if len(value) > 10:
                lines.append(f"  ... and {len(value) - 10} more")
        elif isinstance(value, dict):
            lines.append(f"{key}: {len(value)} entries")
        else:
            lines.append(f"{key}: {value}")

    return "\n".join(lines)


def normalize_severity(severity: Any) -> str:
    """Normalize severity to lowercase string."""
    if isinstance(severity, str):
        return severity.lower()
    elif hasattr(severity, "name"):
        return severity.name.lower()
    elif hasattr(severity, "value"):
        return str(severity.value).lower()
    return str(severity).lower()


def calculate_stats(
    findings: list[dict[str, Any]],
    fail_on_critical: bool,
    fail_on_high: bool,
    fail_on_medium: bool,
) -> dict[str, int]:
    """Calculate test statistics."""
    failures = 0
    skipped = 0

    for finding in findings:
        severity = normalize_severity(finding.get("severity", "medium"))

        is_failure = (
            (severity == "critical" and fail_on_critical)
            or (severity == "high" and fail_on_high)
            or (severity == "medium" and fail_on_medium)
        )

        if is_failure:
            failures += 1
        elif severity in ("low", "info", "informational"):
            skipped += 1

    return {
        "tests": max(len(findings), 1),
        "failures": failures,
        "errors": 0,
        "skipped": skipped,
        "time": len(findings) * 0.001 if findings else 0.001,
    }


def prettify_xml(xml_str: str) -> str:
    """Pretty print XML string."""
    try:
        dom = minidom.parseString(xml_str)
        return dom.toprettyxml(indent="  ", encoding=None)
    except Exception:
        return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_str}'


def get_junit_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of JUnit export results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    return {
        "export_path": ctx.get("junit_export_path", ""),
        "tests": ctx.get("junit_tests_count", 0),
        "failures": ctx.get("junit_failures_count", 0),
        "errors": ctx.get("junit_errors_count", 0),
        "skipped": ctx.get("junit_skipped_count", 0),
    }
