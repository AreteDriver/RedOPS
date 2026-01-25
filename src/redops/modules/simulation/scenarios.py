"""
Scenario generation module.

Generates narrative scenarios explaining potential risk paths.
Produces executive summaries and technical details for different audiences.
Non-exploitative, textual analysis only.
"""

from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from redops.core.context import Context
from redops.core.models import RiskLevel


@dataclass
class AttackScenario:
    """Represents a complete attack scenario."""

    id: int
    title: str
    summary: str
    threat_actor: str
    objective: str
    likelihood: int
    impact: int
    steps: List[Dict[str, Any]]
    mitre_techniques: List[str]
    assets_affected: List[str]
    recommendations: List[str]
    executive_summary: str
    technical_details: str

    @property
    def risk_score(self) -> int:
        """Calculate risk score."""
        return self.likelihood * self.impact

    @property
    def risk_level(self) -> str:
        """Get risk level string."""
        score = self.risk_score
        if score >= 20:
            return "CRITICAL"
        elif score >= 12:
            return "HIGH"
        elif score >= 6:
            return "MEDIUM"
        elif score >= 3:
            return "LOW"
        return "INFO"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "threat_actor": self.threat_actor,
            "objective": self.objective,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "steps": self.steps,
            "mitre_techniques": self.mitre_techniques,
            "assets_affected": self.assets_affected,
            "recommendations": self.recommendations,
            "executive_summary": self.executive_summary,
            "technical_details": self.technical_details,
        }


# Threat actor profiles
THREAT_ACTORS = {
    "opportunistic_attacker": {
        "name": "Opportunistic Attacker",
        "description": "Low-skilled attacker using automated tools and known exploits",
        "motivation": "Financial gain, low-hanging fruit",
        "sophistication": "low",
        "typical_techniques": ["T1595", "T1190", "T1110"],
    },
    "organized_crime": {
        "name": "Organized Cybercrime Group",
        "description": "Well-resourced criminal organization targeting valuable data",
        "motivation": "Financial gain, ransomware, data theft",
        "sophistication": "medium",
        "typical_techniques": ["T1566", "T1078", "T1486", "T1041"],
    },
    "nation_state": {
        "name": "Nation-State Actor",
        "description": "State-sponsored advanced persistent threat",
        "motivation": "Espionage, intellectual property theft, strategic advantage",
        "sophistication": "high",
        "typical_techniques": ["T1199", "T1068", "T1071", "T1567"],
    },
    "insider_threat": {
        "name": "Malicious Insider",
        "description": "Current or former employee with authorized access",
        "motivation": "Financial gain, revenge, ideological",
        "sophistication": "varies",
        "typical_techniques": ["T1078", "T1552", "T1041"],
    },
    "hacktivist": {
        "name": "Hacktivist",
        "description": "Ideologically motivated attacker seeking publicity",
        "motivation": "Political or social statement, reputational damage",
        "sophistication": "low-medium",
        "typical_techniques": ["T1498", "T1190"],
    },
}

# Attack objectives
ATTACK_OBJECTIVES = {
    "data_theft": "Exfiltrate sensitive data for financial gain or competitive advantage",
    "ransomware": "Encrypt critical systems and demand ransom for decryption",
    "disruption": "Disrupt business operations through denial of service",
    "credential_harvesting": "Collect credentials for future attacks or sale",
    "espionage": "Gather intelligence for strategic purposes",
    "reputation_damage": "Damage organizational reputation through defacement or data leak",
    "supply_chain": "Compromise systems to attack downstream customers",
    "cryptomining": "Deploy cryptocurrency miners on compromised infrastructure",
}

# Recommendation templates
RECOMMENDATION_TEMPLATES = {
    "T1190": [
        "Implement a Web Application Firewall (WAF) to filter malicious requests",
        "Keep all applications and frameworks updated with security patches",
        "Conduct regular vulnerability assessments and penetration testing",
    ],
    "T1078": [
        "Implement multi-factor authentication (MFA) for all accounts",
        "Enforce strong password policies and regular rotation",
        "Monitor for unusual account activity and implement anomaly detection",
    ],
    "T1552": [
        "Use a secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager)",
        "Never store credentials in source code or configuration files",
        "Implement credential scanning in CI/CD pipelines",
    ],
    "T1110": [
        "Implement account lockout policies after failed login attempts",
        "Deploy CAPTCHA on authentication endpoints",
        "Use rate limiting to prevent brute force attacks",
    ],
    "T1566": [
        "Deploy advanced email filtering and sandboxing solutions",
        "Conduct regular security awareness training for employees",
        "Implement DMARC, DKIM, and SPF for email authentication",
    ],
    "default": [
        "Implement defense-in-depth security controls",
        "Enable comprehensive logging and monitoring",
        "Develop and test incident response procedures",
        "Conduct regular security assessments",
        "Maintain up-to-date asset inventory",
    ],
}


def generate_scenarios(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Generate narrative attack scenarios from context data.

    Produces detailed scenarios with executive summaries and technical details.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - max_scenarios: Maximum scenarios to generate (default: 5)
            - include_executive_summary: Include C-level summary (default: True)
            - include_technical_details: Include technical details (default: True)

    Returns:
        Updated context with scenarios
    """
    params = params or {}
    max_scenarios = params.get("max_scenarios", 5)
    include_executive = params.get("include_executive_summary", True)
    include_technical = params.get("include_technical_details", True)

    ctx.log("Generating attack scenarios", level="INFO")

    # Get attack paths from context
    attack_paths = ctx.get("attack_paths", [])
    risks = ctx.get("risks", [])
    mitre_mapping = ctx.get("mitre_mapping", {})

    if not attack_paths:
        ctx.log("No attack paths available for scenario generation", level="WARNING")
        ctx.add("scenarios", [])
        return ctx

    # Generate scenarios from top attack paths
    scenarios = []
    for i, path_data in enumerate(attack_paths[:max_scenarios]):
        scenario = create_attack_scenario(
            scenario_id=i + 1,
            attack_path=path_data,
            ctx=ctx,
            include_executive=include_executive,
            include_technical=include_technical,
        )
        scenarios.append(scenario)

    # Prioritize scenarios
    scenarios = prioritize_scenarios(scenarios)

    # Generate overall summary
    overall_summary = generate_overall_summary(scenarios, ctx)

    ctx.add("scenarios", [s.to_dict() for s in scenarios])
    ctx.add("scenario_summary", overall_summary)

    ctx.log(f"Generated {len(scenarios)} attack scenarios", level="INFO")

    return ctx


def create_attack_scenario(
    scenario_id: int,
    attack_path: Dict[str, Any],
    ctx: Context,
    include_executive: bool = True,
    include_technical: bool = True,
) -> AttackScenario:
    """
    Create a complete attack scenario from an attack path.

    Args:
        scenario_id: Unique scenario ID
        attack_path: Attack path data
        ctx: Pipeline context
        include_executive: Include executive summary
        include_technical: Include technical details

    Returns:
        Complete AttackScenario
    """
    # Extract basic info
    name = attack_path.get("name", f"Attack Scenario {scenario_id}")
    description = attack_path.get("description", "")
    steps = attack_path.get("steps", [])
    mitre_techniques = attack_path.get("mitre_techniques", [])
    likelihood = attack_path.get("likelihood", 3)
    impact = attack_path.get("impact", 3)

    # Determine threat actor based on techniques
    threat_actor = determine_threat_actor(mitre_techniques)

    # Determine objective
    objective = determine_objective(steps, mitre_techniques, ctx)

    # Get affected assets
    assets_affected = extract_affected_assets(attack_path, ctx)

    # Generate step details
    detailed_steps = generate_detailed_steps(steps, mitre_techniques)

    # Generate recommendations
    recommendations = generate_recommendations(mitre_techniques, ctx)

    # Generate summaries
    executive_summary = ""
    technical_details = ""

    if include_executive:
        executive_summary = generate_executive_summary(
            name, threat_actor, objective, likelihood, impact, assets_affected
        )

    if include_technical:
        technical_details = generate_technical_details(
            detailed_steps, mitre_techniques, ctx
        )

    return AttackScenario(
        id=scenario_id,
        title=name,
        summary=description,
        threat_actor=threat_actor["name"],
        objective=objective,
        likelihood=likelihood,
        impact=impact,
        steps=detailed_steps,
        mitre_techniques=mitre_techniques,
        assets_affected=assets_affected,
        recommendations=recommendations,
        executive_summary=executive_summary,
        technical_details=technical_details,
    )


def determine_threat_actor(techniques: List[str]) -> Dict[str, Any]:
    """
    Determine the most likely threat actor based on techniques.

    Args:
        techniques: List of MITRE technique IDs

    Returns:
        Threat actor profile
    """
    if not techniques:
        return THREAT_ACTORS["opportunistic_attacker"]

    # Check for specific technique patterns
    nation_state_techniques = {"T1199", "T1068", "T1071", "T1567"}
    ransomware_techniques = {"T1486", "T1041", "T1566"}
    insider_techniques = {"T1078", "T1552"}

    technique_set = set(techniques)

    # Check for nation-state indicators
    if technique_set & nation_state_techniques:
        return THREAT_ACTORS["nation_state"]

    # Check for ransomware/organized crime indicators
    if technique_set & ransomware_techniques:
        return THREAT_ACTORS["organized_crime"]

    # Check for insider threat indicators
    if technique_set & insider_techniques and len(techniques) <= 3:
        return THREAT_ACTORS["insider_threat"]

    # Default to opportunistic
    return THREAT_ACTORS["opportunistic_attacker"]


def determine_objective(
    steps: List[str],
    techniques: List[str],
    ctx: Context
) -> str:
    """
    Determine the attack objective based on steps and techniques.

    Args:
        steps: Attack steps
        techniques: MITRE techniques
        ctx: Pipeline context

    Returns:
        Attack objective description
    """
    technique_set = set(techniques)

    # Check for specific objectives based on techniques
    if "T1486" in technique_set:
        return ATTACK_OBJECTIVES["ransomware"]
    if "T1498" in technique_set:
        return ATTACK_OBJECTIVES["disruption"]
    if {"T1041", "T1567"} & technique_set:
        return ATTACK_OBJECTIVES["data_theft"]
    if {"T1552", "T1110"} & technique_set:
        return ATTACK_OBJECTIVES["credential_harvesting"]

    # Check findings for sensitive data indicators
    for key in ctx.data.keys():
        if key.startswith("finding_"):
            finding = ctx.get(key)
            if finding:
                title = finding.get("title", "").lower()
                if any(kw in title for kw in ["credential", "secret", "key", "password"]):
                    return ATTACK_OBJECTIVES["credential_harvesting"]
                if any(kw in title for kw in ["data", "database", "pii", "sensitive"]):
                    return ATTACK_OBJECTIVES["data_theft"]

    # Default
    return ATTACK_OBJECTIVES["data_theft"]


def extract_affected_assets(attack_path: Dict[str, Any], ctx: Context) -> List[str]:
    """
    Extract affected assets from attack path.

    Args:
        attack_path: Attack path data
        ctx: Pipeline context

    Returns:
        List of affected asset descriptions
    """
    assets = []

    steps = attack_path.get("steps", [])
    for step in steps:
        if isinstance(step, str):
            # Extract asset mentions
            assets.append(step)
        elif isinstance(step, dict):
            node_type = step.get("node_type", "")
            if node_type in ("subdomain", "ip", "technology", "database", "email"):
                assets.append(step.get("description", step.get("action", "")))

    # Deduplicate while preserving order
    seen = set()
    unique_assets = []
    for asset in assets:
        if asset not in seen:
            seen.add(asset)
            unique_assets.append(asset)

    return unique_assets[:10]


def generate_detailed_steps(
    steps: List[str],
    techniques: List[str]
) -> List[Dict[str, Any]]:
    """
    Generate detailed step information.

    Args:
        steps: Basic step descriptions
        techniques: MITRE techniques

    Returns:
        List of detailed step dictionaries
    """
    from redops.modules.simulation.mitre_mapping import MITRE_TECHNIQUES

    detailed = []

    for i, step in enumerate(steps):
        step_dict = {
            "number": i + 1,
            "description": step,
            "phase": get_attack_phase(i, len(steps)),
            "technique": None,
        }

        # Try to associate a technique
        if i < len(techniques):
            technique_id = techniques[i] if i < len(techniques) else None
            if technique_id and technique_id in MITRE_TECHNIQUES:
                tech = MITRE_TECHNIQUES[technique_id]
                step_dict["technique"] = {
                    "id": technique_id,
                    "name": tech.name,
                    "tactic": tech.tactic,
                }

        detailed.append(step_dict)

    return detailed


def get_attack_phase(step_index: int, total_steps: int) -> str:
    """
    Determine the attack phase based on step position.

    Args:
        step_index: Current step index
        total_steps: Total number of steps

    Returns:
        Attack phase name
    """
    if total_steps <= 1:
        return "Execution"

    progress = step_index / (total_steps - 1) if total_steps > 1 else 0

    if progress <= 0.2:
        return "Reconnaissance"
    elif progress <= 0.4:
        return "Initial Access"
    elif progress <= 0.6:
        return "Privilege Escalation"
    elif progress <= 0.8:
        return "Lateral Movement"
    else:
        return "Objective"


def generate_recommendations(techniques: List[str], ctx: Context) -> List[str]:
    """
    Generate recommendations based on techniques used.

    Args:
        techniques: MITRE technique IDs
        ctx: Pipeline context

    Returns:
        List of recommendations
    """
    recommendations = set()

    for technique in techniques:
        if technique in RECOMMENDATION_TEMPLATES:
            recommendations.update(RECOMMENDATION_TEMPLATES[technique])

    # Add default recommendations if we don't have many specific ones
    if len(recommendations) < 3:
        recommendations.update(RECOMMENDATION_TEMPLATES["default"][:3])

    # Check findings for specific recommendations
    for key in ctx.data.keys():
        if key.startswith("finding_"):
            finding = ctx.get(key)
            if finding and finding.get("data", {}).get("recommendation"):
                recommendations.add(finding["data"]["recommendation"])

    return sorted(list(recommendations))[:7]


def generate_executive_summary(
    title: str,
    threat_actor: Dict[str, Any],
    objective: str,
    likelihood: int,
    impact: int,
    assets: List[str]
) -> str:
    """
    Generate an executive summary for C-level stakeholders.

    Args:
        title: Scenario title
        threat_actor: Threat actor profile
        objective: Attack objective
        likelihood: Likelihood score
        impact: Impact score
        assets: Affected assets

    Returns:
        Executive summary text
    """
    risk_score = likelihood * impact
    if risk_score >= 20:
        risk_label = "CRITICAL"
    elif risk_score >= 12:
        risk_label = "HIGH"
    elif risk_score >= 6:
        risk_label = "MEDIUM"
    else:
        risk_label = "LOW"

    summary = f"""## Executive Summary

**Risk Level**: {risk_label} ({risk_score}/25)

**Threat Profile**: This scenario represents a potential attack by a {threat_actor['name'].lower()}, motivated by {threat_actor.get('motivation', 'various factors')}.

**Business Impact**: If successful, this attack could result in {objective.lower()}. The likelihood of this attack occurring is rated {likelihood}/5, with a potential impact of {impact}/5.

**Assets at Risk**: {len(assets)} systems/assets identified in the attack path, including critical infrastructure and data stores.

**Recommendation**: Immediate attention is required to address the vulnerabilities identified in this attack path. Detailed mitigation steps are provided in the technical section below."""

    return summary


def generate_technical_details(
    steps: List[Dict[str, Any]],
    techniques: List[str],
    ctx: Context
) -> str:
    """
    Generate technical details for security teams.

    Args:
        steps: Detailed attack steps
        techniques: MITRE techniques
        ctx: Pipeline context

    Returns:
        Technical details text
    """
    from redops.modules.simulation.mitre_mapping import MITRE_TECHNIQUES

    details = """## Technical Details

### Attack Chain

"""

    for step in steps:
        technique_info = ""
        if step.get("technique"):
            tech = step["technique"]
            technique_info = f" [MITRE: {tech['id']} - {tech['name']}]"

        details += f"**Step {step['number']}** ({step['phase']}): {step['description']}{technique_info}\n\n"

    details += """### MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
"""

    for technique_id in techniques:
        if technique_id in MITRE_TECHNIQUES:
            tech = MITRE_TECHNIQUES[technique_id]
            details += f"| {technique_id} | {tech.name} | {tech.tactic} |\n"

    details += """
### Detection Opportunities

"""

    for technique_id in techniques[:5]:
        if technique_id in MITRE_TECHNIQUES:
            tech = MITRE_TECHNIQUES[technique_id]
            if tech.detection:
                details += f"- **{tech.name}**: {tech.detection}\n"

    return details


def generate_overall_summary(
    scenarios: List[AttackScenario],
    ctx: Context
) -> Dict[str, Any]:
    """
    Generate an overall summary of all scenarios.

    Args:
        scenarios: List of scenarios
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    if not scenarios:
        return {
            "total_scenarios": 0,
            "risk_distribution": {},
            "top_threat_actors": [],
            "most_common_techniques": [],
        }

    # Calculate risk distribution
    risk_distribution = defaultdict(int)
    for scenario in scenarios:
        risk_distribution[scenario.risk_level] += 1

    # Get threat actor distribution
    threat_actors = defaultdict(int)
    for scenario in scenarios:
        threat_actors[scenario.threat_actor] += 1

    # Get most common techniques
    technique_counts = defaultdict(int)
    for scenario in scenarios:
        for tech in scenario.mitre_techniques:
            technique_counts[tech] += 1

    top_techniques = sorted(
        technique_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    return {
        "total_scenarios": len(scenarios),
        "risk_distribution": dict(risk_distribution),
        "average_risk_score": sum(s.risk_score for s in scenarios) / len(scenarios),
        "top_threat_actors": sorted(
            threat_actors.items(),
            key=lambda x: x[1],
            reverse=True
        ),
        "most_common_techniques": top_techniques,
        "critical_count": risk_distribution.get("CRITICAL", 0),
        "high_count": risk_distribution.get("HIGH", 0),
    }


def prioritize_scenarios(
    scenarios: List[AttackScenario]
) -> List[AttackScenario]:
    """
    Prioritize scenarios by risk score.

    Args:
        scenarios: List of scenarios

    Returns:
        Sorted list of scenarios
    """
    return sorted(scenarios, key=lambda s: s.risk_score, reverse=True)


def create_scenario_narrative(
    attack_path: Dict[str, Any], ctx: Context
) -> Dict[str, Any]:
    """
    Create a narrative scenario from an attack path (legacy compatibility).

    Args:
        attack_path: Attack path data
        ctx: Pipeline context

    Returns:
        Scenario narrative dictionary
    """
    scenario = create_attack_scenario(
        scenario_id=1,
        attack_path=attack_path,
        ctx=ctx,
        include_executive=True,
        include_technical=True,
    )
    return scenario.to_dict()


def generate_narrative(attack_path: Dict[str, Any]) -> str:
    """
    Generate a narrative description of an attack path (legacy compatibility).

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
        if isinstance(step, dict):
            step_text = step.get("description", step.get("action", str(step)))
        else:
            step_text = str(step)
        narrative += f"{i}. {step_text}\n"

    return narrative


def get_scenario_by_id(ctx: Context, scenario_id: int) -> Optional[Dict[str, Any]]:
    """
    Get a specific scenario by ID.

    Args:
        ctx: Pipeline context
        scenario_id: Scenario ID

    Returns:
        Scenario dictionary or None
    """
    scenarios = ctx.get("scenarios", [])
    for scenario in scenarios:
        if scenario.get("id") == scenario_id:
            return scenario
    return None


def export_scenarios_markdown(scenarios: List[Dict[str, Any]]) -> str:
    """
    Export scenarios to markdown format.

    Args:
        scenarios: List of scenario dictionaries

    Returns:
        Markdown string
    """
    md = "# Attack Scenarios Report\n\n"

    for scenario in scenarios:
        md += f"## {scenario['title']}\n\n"
        md += f"**Risk Level**: {scenario['risk_level']} (Score: {scenario['risk_score']}/25)\n\n"
        md += f"**Threat Actor**: {scenario['threat_actor']}\n\n"
        md += f"**Objective**: {scenario['objective']}\n\n"

        if scenario.get("executive_summary"):
            md += scenario["executive_summary"] + "\n\n"

        if scenario.get("recommendations"):
            md += "### Recommendations\n\n"
            for rec in scenario["recommendations"]:
                md += f"- {rec}\n"
            md += "\n"

        if scenario.get("technical_details"):
            md += scenario["technical_details"] + "\n\n"

        md += "---\n\n"

    return md
