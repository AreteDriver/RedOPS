"""
Extended MCP tools for RedOPS.

Provides additional tools for threat intelligence, recon, and reporting.
"""

from typing import Any
from pathlib import Path


# Tool definitions for new modules
EXTENDED_TOOLS: dict[str, dict[str, Any]] = {
    "redops_check_ip": {
        "name": "redops_check_ip",
        "description": "Check IP reputation across multiple threat intelligence sources (GreyNoise, AbuseIPDB). Returns threat indicators, abuse scores, and classifications.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address to check (e.g., 8.8.8.8)",
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Threat intel sources to query: greynoise, abuseipdb (default: all)",
                    "default": ["greynoise", "abuseipdb"],
                },
            },
            "required": ["ip"],
        },
    },
    "redops_check_url": {
        "name": "redops_check_url",
        "description": "Check if a URL or host is known to be malicious via URLhaus. Returns threat type, status, and associated malware information.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL or hostname to check",
                },
            },
            "required": ["url"],
        },
    },
    "redops_cert_transparency": {
        "name": "redops_cert_transparency",
        "description": "Search Certificate Transparency logs for a domain. Discovers subdomains from SSL/TLS certificates and identifies certificate issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to search CT logs for (e.g., example.com)",
                },
                "include_expired": {
                    "type": "boolean",
                    "description": "Include expired certificates (default: false)",
                    "default": False,
                },
            },
            "required": ["domain"],
        },
    },
    "redops_asn_lookup": {
        "name": "redops_asn_lookup",
        "description": "Look up ASN (Autonomous System Number) information for an IP, domain, or ASN. Returns network ownership, IP ranges, and organizational details.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, domain, or ASN to look up",
                },
                "include_prefixes": {
                    "type": "boolean",
                    "description": "Include announced IP prefixes (default: true)",
                    "default": True,
                },
                "include_peers": {
                    "type": "boolean",
                    "description": "Include peer information (default: false)",
                    "default": False,
                },
            },
            "required": ["target"],
        },
    },
    "redops_enumerate_subdomains": {
        "name": "redops_enumerate_subdomains",
        "description": "Enumerate subdomains for a domain using multiple techniques (bruteforce, CT logs, DNS). Returns discovered subdomains with resolution status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to enumerate subdomains for",
                },
                "use_ct": {
                    "type": "boolean",
                    "description": "Include Certificate Transparency search (default: true)",
                    "default": True,
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of concurrent threads (default: 10)",
                    "default": 10,
                },
            },
            "required": ["domain"],
        },
    },
    "redops_export_sarif": {
        "name": "redops_export_sarif",
        "description": "Export scan results as a SARIF report for CI/CD integration (GitHub Code Scanning, Azure DevOps).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_data": {
                    "type": "object",
                    "description": "Scan results data to export",
                },
                "output_path": {
                    "type": "string",
                    "description": "Output file path (optional)",
                },
            },
            "required": ["scan_data"],
        },
    },
    "redops_export_junit": {
        "name": "redops_export_junit",
        "description": "Export scan results as JUnit XML for CI/CD pipeline integration (Jenkins, GitLab CI).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_data": {
                    "type": "object",
                    "description": "Scan results data to export",
                },
                "output_path": {
                    "type": "string",
                    "description": "Output file path (optional)",
                },
                "fail_on_high": {
                    "type": "boolean",
                    "description": "Treat high severity findings as failures (default: true)",
                    "default": True,
                },
            },
            "required": ["scan_data"],
        },
    },
    "redops_dashboard_summary": {
        "name": "redops_dashboard_summary",
        "description": "Generate a comprehensive dashboard summary from scan results. Includes risk scores, attack surface metrics, and threat intelligence summary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_data": {
                    "type": "object",
                    "description": "Scan results data to summarize",
                },
            },
            "required": ["scan_data"],
        },
    },
}


async def execute_extended_tool(tool_name: str, arguments: dict[str, Any]) -> Any:
    """
    Execute an extended tool.

    Args:
        tool_name: Name of the tool to execute
        arguments: Tool arguments

    Returns:
        Tool execution result
    """
    if tool_name == "redops_check_ip":
        return await _tool_check_ip(arguments)
    elif tool_name == "redops_check_url":
        return await _tool_check_url(arguments)
    elif tool_name == "redops_cert_transparency":
        return await _tool_cert_transparency(arguments)
    elif tool_name == "redops_asn_lookup":
        return await _tool_asn_lookup(arguments)
    elif tool_name == "redops_enumerate_subdomains":
        return await _tool_enumerate_subdomains(arguments)
    elif tool_name == "redops_export_sarif":
        return await _tool_export_sarif(arguments)
    elif tool_name == "redops_export_junit":
        return await _tool_export_junit(arguments)
    elif tool_name == "redops_dashboard_summary":
        return await _tool_dashboard_summary(arguments)
    else:
        raise ValueError(f"Unknown tool: {tool_name}")


async def _tool_check_ip(arguments: dict[str, Any]) -> dict[str, Any]:
    """Check IP reputation."""
    ip = arguments.get("ip")
    sources = arguments.get("sources", ["greynoise", "abuseipdb"])

    if not ip:
        raise ValueError("IP address is required")

    from redops.core.context import Context

    ctx = Context(target=ip)
    results = {"ip": ip, "sources": {}}

    if "greynoise" in sources:
        try:
            from redops.modules.threat_intel.greynoise import query_greynoise

            ctx = query_greynoise(ctx)
            results["sources"]["greynoise"] = ctx.get("greynoise_result", {})
        except (ImportError, RuntimeError, ValueError, TypeError, ConnectionError, OSError, TimeoutError) as e:
            results["sources"]["greynoise"] = {"error": str(e)}

    if "abuseipdb" in sources:
        try:
            from redops.modules.threat_intel.abuseipdb import check_ip_reputation

            ctx = check_ip_reputation(ctx)
            results["sources"]["abuseipdb"] = ctx.get("abuseipdb_result", {})
        except (ImportError, RuntimeError, ValueError, TypeError, ConnectionError, OSError, TimeoutError) as e:
            results["sources"]["abuseipdb"] = {"error": str(e)}

    return results


async def _tool_check_url(arguments: dict[str, Any]) -> dict[str, Any]:
    """Check URL reputation."""
    url = arguments.get("url")

    if not url:
        raise ValueError("URL is required")

    from redops.core.context import Context
    from redops.modules.threat_intel.urlhaus import check_url

    ctx = Context(target=url)
    ctx = check_url(ctx)

    return {
        "url": url,
        "result": ctx.get("urlhaus_result", {}),
    }


async def _tool_cert_transparency(arguments: dict[str, Any]) -> dict[str, Any]:
    """Search Certificate Transparency logs."""
    domain = arguments.get("domain")
    include_expired = arguments.get("include_expired", False)

    if not domain:
        raise ValueError("Domain is required")

    from redops.core.context import Context
    from redops.modules.recon.cert_transparency import search_ct_logs

    ctx = Context(target=domain)
    ctx = search_ct_logs(ctx, {"include_expired": include_expired})

    return {
        "domain": domain,
        "ct_results": ctx.get("ct_results", {}),
        "subdomains": ctx.get("ct_subdomains", []),
    }


async def _tool_asn_lookup(arguments: dict[str, Any]) -> dict[str, Any]:
    """Look up ASN information."""
    target = arguments.get("target")
    include_prefixes = arguments.get("include_prefixes", True)
    include_peers = arguments.get("include_peers", False)

    if not target:
        raise ValueError("Target is required")

    from redops.core.context import Context
    from redops.modules.recon.asn_lookup import lookup_asn

    ctx = Context(target=target)
    ctx = lookup_asn(
        ctx,
        {
            "include_prefixes": include_prefixes,
            "include_peers": include_peers,
        },
    )

    return {
        "target": target,
        "asn_lookup": ctx.get("asn_lookup", {}),
    }


async def _tool_enumerate_subdomains(arguments: dict[str, Any]) -> dict[str, Any]:
    """Enumerate subdomains."""
    domain = arguments.get("domain")
    use_ct = arguments.get("use_ct", True)
    threads = arguments.get("threads", 10)

    if not domain:
        raise ValueError("Domain is required")

    from redops.core.context import Context
    from redops.modules.recon.subdomain_enum import enumerate_subdomains

    ctx = Context(target=domain)
    ctx = enumerate_subdomains(
        ctx,
        {
            "use_ct": use_ct,
            "threads": threads,
        },
    )

    return {
        "domain": domain,
        "subdomains": ctx.get("subdomains", []),
        "enum_results": ctx.get("subdomain_enum_results", {}),
    }


async def _tool_export_sarif(arguments: dict[str, Any]) -> dict[str, Any]:
    """Export as SARIF."""
    scan_data = arguments.get("scan_data", {})
    output_path = arguments.get("output_path")

    from redops.core.context import Context
    from redops.modules.reporting.sarif_report import export_sarif

    ctx = Context()
    ctx.data = scan_data.get("data", {}) if isinstance(scan_data, dict) else {}

    params = {}
    if output_path:
        params["output_dir"] = str(Path(output_path).parent)
        params["output_name"] = Path(output_path).name

    ctx = export_sarif(ctx, params)

    return {
        "sarif_path": ctx.get("sarif_export_path", ""),
        "results_count": ctx.get("sarif_results_count", 0),
        "rules_count": ctx.get("sarif_rules_count", 0),
    }


async def _tool_export_junit(arguments: dict[str, Any]) -> dict[str, Any]:
    """Export as JUnit XML."""
    scan_data = arguments.get("scan_data", {})
    output_path = arguments.get("output_path")
    fail_on_high = arguments.get("fail_on_high", True)

    from redops.core.context import Context
    from redops.modules.reporting.junit_report import export_junit

    ctx = Context()
    ctx.data = scan_data.get("data", {}) if isinstance(scan_data, dict) else {}

    params = {"fail_on_high": fail_on_high}
    if output_path:
        params["output_dir"] = str(Path(output_path).parent)
        params["output_name"] = Path(output_path).name

    ctx = export_junit(ctx, params)

    return {
        "junit_path": ctx.get("junit_export_path", ""),
        "tests_count": ctx.get("junit_tests_count", 0),
        "failures_count": ctx.get("junit_failures_count", 0),
    }


async def _tool_dashboard_summary(arguments: dict[str, Any]) -> dict[str, Any]:
    """Generate dashboard summary."""
    scan_data = arguments.get("scan_data", {})

    from redops.core.context import Context
    from redops.web.dashboard_widgets import generate_dashboard_data

    ctx = Context()
    ctx.data = scan_data.get("data", {}) if isinstance(scan_data, dict) else {}
    ctx.target = scan_data.get("target", "")

    return generate_dashboard_data(ctx)


# MCP Prompts for common security operations
MCP_PROMPTS: list[dict[str, Any]] = [
    {
        "name": "security-assessment",
        "description": "Comprehensive security assessment prompt for analyzing a target",
        "arguments": [
            {
                "name": "target",
                "description": "Target domain or IP to assess",
                "required": True,
            },
        ],
    },
    {
        "name": "vulnerability-report",
        "description": "Generate a vulnerability report from scan findings",
        "arguments": [
            {
                "name": "findings",
                "description": "JSON string of findings to report on",
                "required": True,
            },
        ],
    },
    {
        "name": "threat-analysis",
        "description": "Analyze threat indicators for an IP or URL",
        "arguments": [
            {
                "name": "indicator",
                "description": "IP address or URL to analyze",
                "required": True,
            },
        ],
    },
]


def get_prompt_content(prompt_name: str, arguments: dict[str, str]) -> str:
    """
    Get the content for a prompt.

    Args:
        prompt_name: Name of the prompt
        arguments: Prompt arguments

    Returns:
        Prompt content string
    """
    if prompt_name == "security-assessment":
        target = arguments.get("target", "")
        return f"""Perform a comprehensive security assessment of {target}:

1. First, run a reconnaissance scan to discover the target's attack surface:
   - Use redops_scan with preset "recon"
   - Check Certificate Transparency logs for subdomains
   - Look up ASN information for network context

2. Check for threat indicators:
   - If IPs are discovered, check their reputation
   - Check any suspicious URLs against URLhaus

3. Analyze the findings:
   - Prioritize by risk level
   - Identify patterns or common issues
   - Note any urgent concerns

4. Provide recommendations:
   - Immediate actions for critical issues
   - Short-term fixes for high/medium risks
   - Long-term security improvements

Target: {target}
"""

    elif prompt_name == "vulnerability-report":
        findings = arguments.get("findings", "{}")
        return f"""Generate a professional vulnerability report from the following findings:

{findings}

The report should include:
1. Executive Summary
   - Overall risk level
   - Key findings count by severity
   - Immediate action items

2. Detailed Findings
   - For each finding: title, severity, description, impact, recommendation

3. Remediation Priority Matrix
   - Ranked by risk and effort

4. Appendices
   - Technical details
   - Evidence/references
"""

    elif prompt_name == "threat-analysis":
        indicator = arguments.get("indicator", "")
        return f"""Analyze the threat indicators for: {indicator}

1. Check reputation:
   - Query GreyNoise for scanner/noise classification
   - Check AbuseIPDB for abuse reports
   - Check URLhaus if it's a URL

2. Gather context:
   - ASN ownership information
   - Geographic location
   - Historical data

3. Assess threat level:
   - Classification (malicious, suspicious, benign)
   - Confidence level
   - Associated threats/campaigns

4. Recommendations:
   - Block/allow decision
   - Monitoring suggestions
   - Related IOCs to check

Indicator: {indicator}
"""

    else:
        return f"Unknown prompt: {prompt_name}"
