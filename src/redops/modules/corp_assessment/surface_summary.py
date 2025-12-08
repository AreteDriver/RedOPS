"""
Surface summary module.

Generates a high-level summary of the attack surface.
"""

from typing import Optional, Dict, Any, List
from redops.core.context import Context


def generate_summary(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Generate a surface summary from collected data.
    
    Args:
        ctx: Pipeline context
        params: Optional parameters
        
    Returns:
        Updated context
    """
    params = params or {}
    
    ctx.log("Generating attack surface summary", level="INFO")
    
    summary = {
        "total_assets": 0,
        "total_risks": 0,
        "exposure_level": "unknown",
        "key_findings": [],
        "recommendations": []
    }
    
    # Count assets
    assets = ctx.get("assets", [])
    summary["total_assets"] = len(assets)
    
    # Count risks
    risks = ctx.get("risks", [])
    summary["total_risks"] = len(risks)
    
    # Determine exposure level
    summary["exposure_level"] = calculate_exposure_level(ctx)
    
    # Extract key findings
    summary["key_findings"] = extract_key_findings(ctx)
    
    # Generate recommendations
    summary["recommendations"] = generate_recommendations(ctx)
    
    ctx.add("surface_summary", summary)
    ctx.log("Surface summary generated", level="INFO")
    
    return ctx


def calculate_exposure_level(ctx: Context) -> str:
    """
    Calculate overall exposure level.
    
    Args:
        ctx: Pipeline context
        
    Returns:
        Exposure level (low, medium, high, critical)
    """
    risks = ctx.get("risks", [])
    
    if not risks:
        return "low"
    
    # Count by severity
    critical = sum(1 for r in risks if r.get("level") == "critical")
    high = sum(1 for r in risks if r.get("level") == "high")
    
    if critical > 0:
        return "critical"
    elif high > 3:
        return "high"
    elif high > 0:
        return "medium"
    else:
        return "low"


def extract_key_findings(ctx: Context, limit: int = 5) -> List[str]:
    """
    Extract key findings from context.
    
    Args:
        ctx: Pipeline context
        limit: Maximum number of findings
        
    Returns:
        List of key finding descriptions
    """
    findings = []
    
    # Get top risks
    risks = ctx.get("risks", [])
    if risks:
        # Sort by score
        sorted_risks = sorted(risks, key=lambda r: r.get("score", 0), reverse=True)
        
        for risk in sorted_risks[:limit]:
            findings.append(risk.get("title", "Unknown risk"))
    
    return findings


def generate_recommendations(ctx: Context) -> List[str]:
    """
    Generate recommendations based on findings.
    
    Args:
        ctx: Pipeline context
        
    Returns:
        List of recommendations
    """
    recommendations = []
    
    exposure_level = calculate_exposure_level(ctx)
    
    if exposure_level in ["critical", "high"]:
        recommendations.append("Immediate action required to address critical risks")
        recommendations.append("Conduct thorough security audit")
        recommendations.append("Implement incident response plan")
    
    if exposure_level in ["medium", "high", "critical"]:
        recommendations.append("Review and update security policies")
        recommendations.append("Enhance monitoring and logging")
    
    recommendations.append("Conduct regular security assessments")
    recommendations.append("Provide security awareness training")
    recommendations.append("Maintain asset inventory")
    
    return recommendations[:5]
