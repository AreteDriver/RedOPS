"""
HTML report generation module.

Generates HTML reports with optional styling.
"""

from typing import Optional, Dict, Any
from pathlib import Path
from datetime import datetime
from redops.core.context import Context


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedOps Report - {target}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
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
        .risk-critical {{ color: #dc3545; font-weight: bold; }}
        .risk-high {{ color: #fd7e14; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        .risk-low {{ color: #28a745; }}
        .risk-info {{ color: #17a2b8; }}
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
    output_dir = Path(params.get('output_dir', './output'))
    output_dir.mkdir(parents=True, exist_ok=True)
    
    ctx.log("Generating HTML report", level="INFO")
    
    # Build the report content
    content = build_html_content(ctx)
    
    # Fill in the template
    html = HTML_TEMPLATE.format(
        target=ctx.target or "N/A",
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        pipeline=ctx.get("pipeline_name", "Unknown"),
        content=content
    )
    
    # Save to file
    output_path = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(output_path, 'w') as f:
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
    
    # Summary section
    content += '<div class="section">\n'
    content += '<h2>Summary</h2>\n'
    
    risks = ctx.get("risks", [])
    if risks:
        content += f'<p>Total risks identified: <strong>{len(risks)}</strong></p>\n'
    else:
        content += '<p>No significant risks identified.</p>\n'
    
    content += '</div>\n'
    
    # Risks section
    if risks:
        content += '<div class="section">\n'
        content += '<h2>Identified Risks</h2>\n'
        content += '<table>\n'
        content += '<tr><th>Title</th><th>Level</th><th>Score</th><th>Description</th></tr>\n'
        
        for risk in risks[:10]:  # Top 10 risks
            level = risk.get("level", "info")
            title = risk.get("title", "Untitled")
            score = risk.get("score", 0)
            desc = risk.get("description", "")[:100]
            
            content += f'<tr><td>{title}</td>'
            content += f'<td class="risk-{level}">{level.upper()}</td>'
            content += f'<td>{score}</td>'
            content += f'<td>{desc}</td></tr>\n'
        
        content += '</table>\n'
        content += '</div>\n'
    
    # Attack paths section
    attack_paths = ctx.get("attack_paths", [])
    if attack_paths:
        content += '<div class="section">\n'
        content += '<h2>Attack Paths</h2>\n'
        
        for i, path in enumerate(attack_paths[:5], 1):
            name = path.get("name", f"Path {i}")
            desc = path.get("description", "")
            steps = path.get("steps", [])
            
            content += f'<h3>{i}. {name}</h3>\n'
            content += f'<p>{desc}</p>\n'
            
            if steps:
                content += '<ol>\n'
                for step in steps:
                    content += f'<li>{step}</li>\n'
                content += '</ol>\n'
        
        content += '</div>\n'
    
    return content
