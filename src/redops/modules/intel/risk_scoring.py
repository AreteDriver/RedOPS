"""
Risk scoring module.

Calculates and assigns risk scores to findings and assets.
"""

from typing import Optional, Dict, Any, List
from redops.core.context import Context
from redops.core.models import Risk, RiskLevel


def score_risks(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Calculate risk scores for findings in the context.
    
    Args:
        ctx: Pipeline context
        params: Optional parameters
        
    Returns:
        Updated context
    """
    params = params or {}
    
    ctx.log("Scoring risks", level="INFO")
    
    risks = []
    
    # Example: Create sample risks based on context data
    findings = ctx.get("findings", [])
    
    # Placeholder: Real implementation would analyze findings
    # and create risk objects with proper scoring
    
    ctx.add("risks", [r.model_dump() for r in risks])
    ctx.log(f"Risk scoring completed, identified {len(risks)} risks", level="INFO")
    
    return ctx


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Calculate risk score from likelihood and impact.
    
    Args:
        likelihood: Likelihood score (1-5)
        impact: Impact score (1-5)
        
    Returns:
        Risk score (likelihood × impact)
    """
    return likelihood * impact


def categorize_risk(score: int) -> RiskLevel:
    """
    Categorize a risk based on its score.
    
    Args:
        score: Risk score
        
    Returns:
        Risk level
    """
    if score >= 20:
        return RiskLevel.CRITICAL
    elif score >= 12:
        return RiskLevel.HIGH
    elif score >= 6:
        return RiskLevel.MEDIUM
    elif score >= 3:
        return RiskLevel.LOW
    return RiskLevel.INFO


def aggregate_risks(risks: List[Risk]) -> Dict[str, Any]:
    """
    Aggregate risk statistics.
    
    Args:
        risks: List of risks
        
    Returns:
        Aggregated statistics
    """
    stats = {
        "total": len(risks),
        "by_level": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "by_category": {},
        "average_score": 0
    }
    
    if not risks:
        return stats
    
    total_score = 0
    
    for risk in risks:
        level = risk.level.value
        stats["by_level"][level] = stats["by_level"].get(level, 0) + 1
        
        if risk.category:
            cat = risk.category.value
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        
        total_score += risk.score
    
    stats["average_score"] = total_score / len(risks)
    
    return stats
