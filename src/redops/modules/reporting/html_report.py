"""
HTML report generation module.

Generates HTML reports with interactive MITRE matrix, risk charts, and attack path diagrams.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime
import html
import json
from redops.core.context import Context


# MITRE ATT&CK tactics in kill chain order
MITRE_TACTICS_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Risk level colors
RISK_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#17a2b8",
}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedOps Report - {target}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
        }}
        .meta {{
            opacity: 0.9;
            margin-top: 10px;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            margin-top: 0;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        .collapsible::after {{
            content: ' ▼';
            font-size: 0.8em;
        }}
        .collapsible.collapsed::after {{
            content: ' ▶';
        }}
        .collapsible-content {{
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        .collapsible-content.collapsed {{
            max-height: 0;
            padding: 0;
        }}
        .risk-critical {{ color: var(--critical); font-weight: bold; }}
        .risk-high {{ color: var(--high); font-weight: bold; }}
        .risk-medium {{ color: var(--medium); font-weight: bold; }}
        .risk-low {{ color: var(--low); }}
        .risk-info {{ color: var(--info); }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }}
        .badge-critical {{ background: var(--critical); }}
        .badge-high {{ background: var(--high); }}
        .badge-medium {{ background: var(--medium); color: #333; }}
        .badge-low {{ background: var(--low); }}
        .badge-info {{ background: var(--info); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .mitre-matrix {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }}
        .mitre-tactic {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 10px;
            min-height: 100px;
        }}
        .mitre-tactic h4 {{
            margin: 0 0 10px 0;
            font-size: 0.85em;
            color: #667eea;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }}
        .mitre-technique {{
            background: #667eea;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            margin: 2px 0;
            display: block;
        }}
        .mitre-technique:hover {{
            background: #764ba2;
        }}
        .risk-chart {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}
        .risk-bar {{
            flex: 1;
            text-align: center;
        }}
        .risk-bar-fill {{
            height: 20px;
            border-radius: 10px;
            margin-bottom: 5px;
        }}
        .attack-path {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
        }}
        .attack-path.critical {{ border-left-color: var(--critical); }}
        .attack-path.high {{ border-left-color: var(--high); }}
        .attack-path.medium {{ border-left-color: var(--medium); }}
        .path-steps {{
            font-family: monospace;
            background: #fff;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .stat-label {{
            opacity: 0.9;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            opacity: 0.6;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RedOps Security Assessment Report</h1>
        <div class="meta">
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Pipeline:</strong> {pipeline}</p>
        </div>
    </div>
    
    {content}
    
    <div class="footer">
        <p>Generated automatically by RedOps Framework</p>
    </div>

    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(function(el) {{
            el.addEventListener('click', function() {{
                this.classList.toggle('collapsed');
                var content = this.nextElementSibling;
                if (content && content.classList.contains('collapsible-content')) {{
                    content.classList.toggle('collapsed');
                }}
            }});
        }});

        // Print button
        if (document.querySelector('.print-btn')) {{
            document.querySelector('.print-btn').addEventListener('click', function() {{
                window.print();
            }});
        }}
    </script>
</body>
</html>
"""


def generate_html(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Generate an HTML report.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Generating HTML report", level="INFO")

    # Build the report content
    content = build_html_content(ctx)

    # Fill in the template
    html = HTML_TEMPLATE.format(
        target=ctx.target or "N/A",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        pipeline=ctx.get("pipeline_name", "Unknown"),
        content=content,
    )

    # Save to file
    output_path = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(output_path, "w") as f:
        f.write(html)

    ctx.add("html_report_path", str(output_path))
    ctx.log(f"HTML report saved to {output_path}", level="INFO")

    return ctx


def build_html_content(ctx: Context) -> str:
    """
    Build the HTML report content sections.

    Args:
        ctx: Pipeline context

    Returns:
        HTML content string
    """
    content = ""

    # Stats overview section
    content += build_stats_overview(ctx)

    # Risk summary section
    risks = ctx.get("risks", [])
    content += build_risk_section(risks)

    # MITRE ATT&CK matrix section
    content += build_mitre_matrix_html(ctx)

    # Attack paths section
    attack_paths = ctx.get("attack_paths", [])
    content += build_attack_paths_html(attack_paths)

    # Scenarios section
    scenarios = ctx.get("scenarios", [])
    content += build_scenarios_html(scenarios)

    # Detailed findings section
    content += build_detailed_findings_html(ctx)

    return content


def build_stats_overview(ctx: Context) -> str:
    """Build statistics overview cards."""
    content = '<div class="section">\n'
    content += "<h2>Assessment Overview</h2>\n"
    content += '<div class="stats-grid">\n'

    # Total risks
    risks = ctx.get("risks", [])
    content += f'''
    <div class="stat-card">
        <div class="stat-value">{len(risks)}</div>
        <div class="stat-label">Total Risks</div>
    </div>
    '''

    # Critical/High risks
    critical = sum(1 for r in risks if r.get("level", "").lower() == "critical")
    high = sum(1 for r in risks if r.get("level", "").lower() == "high")
    content += f'''
    <div class="stat-card" style="background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%);">
        <div class="stat-value">{critical + high}</div>
        <div class="stat-label">Critical/High Risks</div>
    </div>
    '''

    # Attack paths
    attack_paths = ctx.get("attack_paths", [])
    content += f'''
    <div class="stat-card">
        <div class="stat-value">{len(attack_paths)}</div>
        <div class="stat-label">Attack Paths</div>
    </div>
    '''

    # MITRE techniques
    mitre_techniques = ctx.get("mitre_techniques_used", [])
    content += f'''
    <div class="stat-card">
        <div class="stat-value">{len(mitre_techniques)}</div>
        <div class="stat-label">MITRE Techniques</div>
    </div>
    '''

    content += "</div>\n</div>\n"
    return content


def build_risk_section(risks: List[Dict[str, Any]]) -> str:
    """Build risk analysis section with chart."""
    content = '<div class="section">\n'
    content += "<h2>Risk Analysis</h2>\n"

    if not risks:
        content += "<p>No significant risks identified.</p>\n"
        content += "</div>\n"
        return content

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for risk in risks:
        level = risk.get("level", risk.get("severity", "info")).lower()
        if level in severity_counts:
            severity_counts[level] += 1
        else:
            severity_counts["info"] += 1

    # Risk distribution chart
    total = max(len(risks), 1)
    content += '<div class="risk-chart">\n'
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts[severity]
        pct = (count / total) * 100
        color = RISK_COLORS.get(severity, "#ccc")
        content += f'''
        <div class="risk-bar">
            <div class="risk-bar-fill" style="background: {color}; width: {max(pct, 5)}%;"></div>
            <strong>{severity.upper()}</strong><br>{count}
        </div>
        '''
    content += "</div>\n"

    # Risk table
    content += "<table>\n"
    content += "<tr><th>Severity</th><th>Title</th><th>Score</th><th>Description</th></tr>\n"

    sorted_risks = sorted(
        risks,
        key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            r.get("level", "info").lower(), 5
        )
    )

    for risk in sorted_risks[:15]:
        level = risk.get("level", risk.get("severity", "info")).lower()
        title = html.escape(risk.get("title", "Untitled"))
        score = risk.get("score", 0)
        desc = html.escape(risk.get("description", "")[:150])

        content += f"<tr>"
        content += f'<td><span class="badge badge-{level}">{level.upper()}</span></td>'
        content += f"<td>{title}</td>"
        content += f"<td>{score}</td>"
        content += f"<td>{desc}</td>"
        content += "</tr>\n"

    content += "</table>\n"

    if len(risks) > 15:
        content += f"<p><em>... and {len(risks) - 15} more risks.</em></p>\n"

    content += "</div>\n"
    return content


def build_mitre_matrix_html(ctx: Context) -> str:
    """Build MITRE ATT&CK matrix visualization."""
    mitre_mapping = ctx.get("mitre_mapping", {})
    mitre_techniques = set(ctx.get("mitre_techniques_used", []))

    if not mitre_mapping and not mitre_techniques:
        return ""

    content = '<div class="section">\n'
    content += "<h2>MITRE ATT&CK Coverage</h2>\n"

    # Build matrix view from mapping
    matrix = {}
    for technique_id, technique_info in mitre_mapping.items():
        if isinstance(technique_info, dict):
            tactic = technique_info.get("tactic", "Unknown")
            name = technique_info.get("name", technique_id)
        else:
            tactic = "Unknown"
            name = technique_id
        if tactic not in matrix:
            matrix[tactic] = []
        matrix[tactic].append({"id": technique_id, "name": name})

    # If no mapping but have technique IDs, just use IDs
    if not matrix and mitre_techniques:
        matrix["Identified Techniques"] = [{"id": t, "name": t} for t in sorted(mitre_techniques)]

    content += '<div class="mitre-matrix">\n'

    for tactic in MITRE_TACTICS_ORDER:
        techniques = matrix.get(tactic, [])
        if techniques or tactic in matrix:
            content += '<div class="mitre-tactic">\n'
            content += f"<h4>{tactic}</h4>\n"
            for tech in techniques[:8]:  # Limit display
                tech_id = tech.get("id", "")
                tech_name = html.escape(tech.get("name", tech_id))
                content += f'<span class="mitre-technique" title="{tech_name}">{tech_id}</span>\n'
            if len(techniques) > 8:
                content += f'<span class="mitre-technique" style="background: #999;">+{len(techniques) - 8} more</span>\n'
            content += "</div>\n"

    # Add "Unknown" tactic if present
    if "Unknown" in matrix:
        techniques = matrix["Unknown"]
        content += '<div class="mitre-tactic">\n'
        content += "<h4>Other</h4>\n"
        for tech in techniques[:8]:
            tech_id = tech.get("id", "")
            content += f'<span class="mitre-technique">{tech_id}</span>\n'
        content += "</div>\n"

    content += "</div>\n"

    # Summary stats
    total_techniques = sum(len(v) for v in matrix.values())
    tactics_covered = len([t for t in matrix if matrix.get(t)])
    content += f"<p><strong>Total:</strong> {total_techniques} techniques across {tactics_covered} tactics</p>\n"

    content += "</div>\n"
    return content


def build_attack_paths_html(attack_paths: List[Dict[str, Any]]) -> str:
    """Build attack paths visualization."""
    if not attack_paths:
        return ""

    content = '<div class="section">\n'
    content += f"<h2>Attack Paths ({len(attack_paths)} identified)</h2>\n"

    sorted_paths = sorted(
        attack_paths,
        key=lambda p: p.get("likelihood", 0) * p.get("impact", 0),
        reverse=True
    )

    for i, path in enumerate(sorted_paths[:5], 1):
        name = html.escape(path.get("name", f"Attack Path {i}"))
        description = html.escape(path.get("description", ""))
        likelihood = path.get("likelihood", 0)
        impact = path.get("impact", 0)
        risk_score = likelihood * impact
        steps = path.get("steps", [])
        mitre_techniques = path.get("mitre_techniques", [])

        # Determine risk level
        if risk_score >= 20:
            risk_class = "critical"
            risk_level = "CRITICAL"
        elif risk_score >= 12:
            risk_class = "high"
            risk_level = "HIGH"
        elif risk_score >= 6:
            risk_class = "medium"
            risk_level = "MEDIUM"
        else:
            risk_class = "low"
            risk_level = "LOW"

        content += f'<div class="attack-path {risk_class}">\n'
        content += f"<h3>{i}. {name}</h3>\n"
        content += f'<span class="badge badge-{risk_class}">{risk_level}</span> '
        content += f"Risk Score: {risk_score} (Likelihood: {likelihood}/5, Impact: {impact}/5)\n"

        if description:
            content += f"<p>{description}</p>\n"

        if mitre_techniques:
            content += "<p><strong>MITRE Techniques:</strong> "
            content += ", ".join(mitre_techniques[:5])
            if len(mitre_techniques) > 5:
                content += f" (+{len(mitre_techniques) - 5} more)"
            content += "</p>\n"

        if steps:
            content += '<div class="path-steps">\n'
            for j, step in enumerate(steps):
                if isinstance(step, dict):
                    step_name = html.escape(step.get("name", step.get("node", f"Step {j+1}")))
                else:
                    step_name = html.escape(str(step))

                if j == 0:
                    content += f"[ENTRY] {step_name}<br>\n"
                elif j == len(steps) - 1:
                    content += f"&nbsp;&nbsp;&nbsp;└──▶ [TARGET] {step_name}<br>\n"
                else:
                    content += f"&nbsp;&nbsp;&nbsp;├──▶ {step_name}<br>\n"
            content += "</div>\n"

        content += "</div>\n"

    if len(attack_paths) > 5:
        content += f"<p><em>... and {len(attack_paths) - 5} more attack paths.</em></p>\n"

    content += "</div>\n"
    return content


def build_scenarios_html(scenarios: List[Dict[str, Any]]) -> str:
    """Build attack scenarios section."""
    if not scenarios:
        return ""

    content = '<div class="section">\n'
    content += f"<h2>Threat Scenarios ({len(scenarios)} modeled)</h2>\n"

    for i, scenario in enumerate(scenarios[:3], 1):
        name = html.escape(scenario.get("name", f"Scenario {i}"))
        threat_actor = scenario.get("threat_actor", {})
        objective = html.escape(scenario.get("objective", "Unknown"))
        risk_level = scenario.get("risk_level", "MEDIUM").upper()
        executive_summary = html.escape(scenario.get("executive_summary", ""))

        risk_class = risk_level.lower()
        if risk_class not in ["critical", "high", "medium", "low", "info"]:
            risk_class = "medium"

        content += f'<div class="attack-path {risk_class}">\n'
        content += f"<h3>{i}. {name}</h3>\n"
        content += f'<span class="badge badge-{risk_class}">{risk_level}</span>\n'

        if isinstance(threat_actor, dict):
            actor_name = html.escape(threat_actor.get("name", "Unknown"))
            content += f"<p><strong>Threat Actor:</strong> {actor_name}</p>\n"
        elif threat_actor:
            content += f"<p><strong>Threat Actor:</strong> {html.escape(str(threat_actor))}</p>\n"

        content += f"<p><strong>Objective:</strong> {objective}</p>\n"

        if executive_summary:
            summary_preview = executive_summary[:400]
            if len(executive_summary) > 400:
                summary_preview += "..."
            content += f"<p>{summary_preview}</p>\n"

        content += "</div>\n"

    if len(scenarios) > 3:
        content += f"<p><em>... and {len(scenarios) - 3} more scenarios.</em></p>\n"

    content += "</div>\n"
    return content


def build_detailed_findings_html(ctx: Context) -> str:
    """Build detailed findings section."""
    content = '<div class="section">\n'
    content += '<h2 class="collapsible">Technical Details</h2>\n'
    content += '<div class="collapsible-content">\n'

    # List all data keys with sizes
    content += "<table>\n"
    content += "<tr><th>Data Key</th><th>Type</th><th>Size</th></tr>\n"

    for key, value in ctx.data.items():
        if key.startswith("_"):
            continue
        key_escaped = html.escape(key)
        value_type = type(value).__name__
        if isinstance(value, (list, dict)):
            size = len(value)
        elif isinstance(value, str):
            size = f"{len(value)} chars"
        else:
            size = "-"
        content += f"<tr><td>{key_escaped}</td><td>{value_type}</td><td>{size}</td></tr>\n"

    content += "</table>\n"
    content += "</div>\n</div>\n"

    return content
