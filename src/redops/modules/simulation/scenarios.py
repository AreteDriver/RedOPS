"""
Scenario generation module.

Generates narrative scenarios explaining potential risk paths.
Non-exploitative, textual analysis only.
"""

from typing import Optional, Dict, Any, List
from redops.core.context import Context
from redops.core.models import AttackPath


def generate_scenarios(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Generate narrative scenarios from attack paths.
    
    Args:
        ctx: Pipeline context
        params: Optional parameters
        
    Returns:
        Updated context
    """
    params = params or {}
    
    ctx.log("Generating attack scenarios", level="INFO")
    
    # Get attack paths from context
    attack_paths = ctx.get("attack_paths", [])
    
    scenarios = []
    for path_data in attack_paths[:5]:  # Top 5 paths
        scenario = create_scenario_narrative(path_data, ctx)
        scenarios.append(scenario)
    
    ctx.add("scenarios", scenarios)
    ctx.log(f"Generated {len(scenarios)} scenarios", level="INFO")
    
    return ctx


def create_scenario_narrative(attack_path: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Create a narrative scenario from an attack path.
    
    Args:
        attack_path: Attack path data
        ctx: Pipeline context
        
    Returns:
        Scenario narrative
    """
    scenario = {
        "title": attack_path.get("name", "Unnamed Scenario"),
        "description": attack_path.get("description", ""),
        "likelihood": attack_path.get("likelihood", 0),
        "impact": attack_path.get("impact", 0),
        "narrative": generate_narrative(attack_path),
        "recommendations": generate_recommendations(attack_path)
    }
    
    return scenario


def generate_narrative(attack_path: Dict[str, Any]) -> str:
    """
    Generate a narrative description of an attack path.
    
    Args:
        attack_path: Attack path data
        
    Returns:
        Narrative string
    """
    steps = attack_path.get("steps", [])
    
    if not steps:
        return "No detailed steps available for this scenario."
    
    narrative = f"This scenario involves {len(steps)} steps:\n\n"
    
    for i, step in enumerate(steps, 1):
        narrative += f"{i}. {step}\n"
    
    return narrative


def generate_recommendations(attack_path: Dict[str, Any]) -> List[str]:
    """
    Generate recommendations to mitigate an attack path.
    
    Args:
        attack_path: Attack path data
        
    Returns:
        List of recommendations
    """
    recommendations = [
        "Implement least privilege access controls",
        "Enable comprehensive logging and monitoring",
        "Regularly update and patch all systems",
        "Conduct security awareness training",
        "Implement network segmentation"
    ]
    
    # Placeholder: Real implementation would generate specific
    # recommendations based on the attack path
    
    return recommendations[:3]


def prioritize_scenarios(scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prioritize scenarios by risk score.
    
    Args:
        scenarios: List of scenarios
        
    Returns:
        Sorted list of scenarios
    """
    def risk_score(scenario: Dict[str, Any]) -> int:
        return scenario.get("likelihood", 0) * scenario.get("impact", 0)
    
    return sorted(scenarios, key=risk_score, reverse=True)
