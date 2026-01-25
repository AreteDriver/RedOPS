"""
AI Assistant Module for RedOPS.

Provides AI-powered analysis, explanations, and recommendations
for security assessment findings using OpenAI or Anthropic APIs.
"""

import os
import json
from typing import Dict, Any, Optional, List
from pathlib import Path


def load_config() -> Dict[str, Any]:
    """Load configuration from file."""
    config_path = Path.home() / ".config" / "redops" / "config.json"
    env_path = os.environ.get("REDOPS_CONFIG")
    if env_path:
        config_path = Path(env_path)

    if config_path.exists():
        with open(config_path, 'r') as f:
            return json.load(f)
    return {}


def get_api_key(provider: str) -> Optional[str]:
    """Get API key for a provider."""
    # Check environment variable first
    env_var = f"{provider.upper()}_API_KEY"
    env_key = os.getenv(env_var)
    if env_key:
        return env_key

    # Check config file
    config = load_config()
    return config.get("api_keys", {}).get(provider)


class AIAssistant:
    """AI-powered assistant for security analysis."""

    def __init__(self, provider: str = None, model: str = None):
        """
        Initialize the AI assistant.

        Args:
            provider: AI provider (openai, anthropic). Defaults to config.
            model: Model to use. Defaults to config.
        """
        config = load_config()
        ai_config = config.get("ai", {})

        self.provider = provider or ai_config.get("provider", "openai")
        self.model = model or ai_config.get("model", "gpt-4o-mini")
        self.max_tokens = ai_config.get("max_tokens", 2048)
        self.temperature = ai_config.get("temperature", 0.7)

        # Get API key
        self.api_key = get_api_key(self.provider)
        if not self.api_key:
            raise ValueError(
                f"No API key found for {self.provider}. "
                f"Set {self.provider.upper()}_API_KEY environment variable or "
                f"use 'redops settings' to configure."
            )

        # Initialize client
        self._init_client()

    def _init_client(self):
        """Initialize the appropriate API client."""
        if self.provider == "openai":
            try:
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "OpenAI library not installed. "
                    "Install with: pip install openai"
                )
        elif self.provider == "anthropic":
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "Anthropic library not installed. "
                    "Install with: pip install anthropic"
                )
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _call_api(self, prompt: str, system_prompt: str = None) -> str:
        """Call the AI API with the given prompt."""
        if self.provider == "openai":
            return self._call_openai(prompt, system_prompt)
        elif self.provider == "anthropic":
            return self._call_anthropic(prompt, system_prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _call_openai(self, prompt: str, system_prompt: str = None) -> str:
        """Call OpenAI API."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )

        return response.choices[0].message.content

    def _call_anthropic(self, prompt: str, system_prompt: str = None) -> str:
        """Call Anthropic API."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt or "You are a security analysis assistant.",
            messages=[
                {"role": "user", "content": prompt}
            ],
        )

        return response.content[0].text

    def analyze_findings(self, scan_data: Dict[str, Any]) -> str:
        """
        Analyze security scan findings and provide insights.

        Args:
            scan_data: Dictionary containing scan results

        Returns:
            AI-generated analysis of findings
        """
        system_prompt = """You are an expert cybersecurity analyst. Analyze the provided
security scan results and provide:
1. A summary of the most critical findings
2. Risk assessment for each major finding
3. Potential attack vectors identified
4. Prioritized list of issues to address

Be concise but thorough. Focus on actionable insights."""

        # Extract key findings
        findings_summary = self._extract_findings_summary(scan_data)

        prompt = f"""Analyze these security scan findings:

{json.dumps(findings_summary, indent=2)}

Provide a comprehensive security analysis."""

        return self._call_api(prompt, system_prompt)

    def explain(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Explain a security concept or finding.

        Args:
            query: The question or topic to explain
            context: Optional context data

        Returns:
            AI-generated explanation
        """
        system_prompt = """You are a security education expert. Provide clear,
accurate explanations of security concepts, vulnerabilities, and best practices.
Include practical examples where helpful. Make explanations accessible but technically accurate."""

        prompt = query
        if context:
            prompt = f"""Context: {json.dumps(context, indent=2)}

Question: {query}"""

        return self._call_api(prompt, system_prompt)

    def suggest_remediations(self, scan_data: Dict[str, Any]) -> str:
        """
        Suggest remediations for identified security issues.

        Args:
            scan_data: Dictionary containing scan results

        Returns:
            AI-generated remediation suggestions
        """
        system_prompt = """You are a security remediation specialist. For each
identified security issue, provide:
1. Specific remediation steps
2. Priority level (Critical, High, Medium, Low)
3. Estimated effort
4. Prevention measures for the future

Format your response clearly with actionable steps."""

        findings_summary = self._extract_findings_summary(scan_data)

        prompt = f"""Based on these security scan findings, provide remediation recommendations:

{json.dumps(findings_summary, indent=2)}

For each finding, suggest specific fixes and preventive measures."""

        return self._call_api(prompt, system_prompt)

    def summarize(self, scan_data: Dict[str, Any]) -> str:
        """
        Generate an executive summary of scan results.

        Args:
            scan_data: Dictionary containing scan results

        Returns:
            AI-generated executive summary
        """
        system_prompt = """You are preparing a security briefing for executives.
Create a clear, non-technical summary that highlights:
1. Overall security posture (Good/Moderate/Poor)
2. Key risks in business terms
3. Recommended immediate actions
4. Resource requirements for remediation

Keep it concise and focused on business impact."""

        findings_summary = self._extract_findings_summary(scan_data)

        prompt = f"""Create an executive summary for these security scan results:

{json.dumps(findings_summary, indent=2)}

Focus on business impact and prioritized recommendations."""

        return self._call_api(prompt, system_prompt)

    def chat(self, message: str, context: Dict[str, Any] = None) -> str:
        """
        Interactive chat for security questions.

        Args:
            message: User message
            context: Optional context from scan data

        Returns:
            AI response
        """
        system_prompt = """You are a helpful security assistant for RedOPS,
a security assessment framework. Help users understand:
- Security scan results and findings
- Cybersecurity concepts and best practices
- Remediation strategies
- Threat intelligence

Be helpful, accurate, and security-focused. If you're unsure about something,
say so rather than guessing."""

        prompt = message
        if context:
            prompt = f"""Available scan context:
{json.dumps(self._extract_findings_summary(context), indent=2)}

User question: {message}"""

        return self._call_api(prompt, system_prompt)

    def correlate_threats(self, scan_data: Dict[str, Any]) -> str:
        """
        Correlate findings with known threat patterns.

        Args:
            scan_data: Dictionary containing scan results

        Returns:
            AI-generated threat correlation analysis
        """
        system_prompt = """You are a threat intelligence analyst. Analyze the
provided findings and:
1. Identify patterns that match known attack techniques
2. Map findings to MITRE ATT&CK framework where applicable
3. Identify potential threat actors or campaign types
4. Suggest additional indicators to look for

Be specific about technique IDs and threat patterns."""

        findings_summary = self._extract_findings_summary(scan_data)

        prompt = f"""Correlate these findings with known threat patterns:

{json.dumps(findings_summary, indent=2)}

Identify attack techniques, potential threat actors, and MITRE ATT&CK mappings."""

        return self._call_api(prompt, system_prompt)

    def generate_report_section(
        self,
        scan_data: Dict[str, Any],
        section_type: str = "executive"
    ) -> str:
        """
        Generate a specific section of a security report.

        Args:
            scan_data: Dictionary containing scan results
            section_type: Type of section (executive, technical, recommendations)

        Returns:
            AI-generated report section
        """
        section_prompts = {
            "executive": "Write an executive summary section for a security report.",
            "technical": "Write a technical findings section with detailed analysis.",
            "recommendations": "Write a recommendations section with prioritized actions.",
            "risk": "Write a risk assessment section with scoring and business impact.",
            "compliance": "Write a compliance implications section.",
        }

        system_prompt = f"""You are writing a professional security assessment report.
{section_prompts.get(section_type, section_prompts['executive'])}

Use professional language, be specific about findings, and ensure the content
is suitable for formal documentation."""

        findings_summary = self._extract_findings_summary(scan_data)

        prompt = f"""Generate a {section_type} section based on these findings:

{json.dumps(findings_summary, indent=2)}"""

        return self._call_api(prompt, system_prompt)

    def _extract_findings_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key findings from scan data for AI processing."""
        summary = {
            "target": scan_data.get("target", "Unknown"),
            "scan_time": scan_data.get("timestamp", "Unknown"),
        }

        # Extract exposures
        exposure = scan_data.get("exposure_scan", {})
        if exposure:
            summary["exposures"] = exposure.get("exposures", [])[:10]

        # Extract threat intel
        threat_intel = scan_data.get("threat_intel", {})
        if threat_intel:
            summary["threat_indicators"] = threat_intel.get("iocs", [])[:10]

        # Extract compliance gaps
        compliance = scan_data.get("compliance", {})
        if compliance:
            summary["compliance_gaps"] = compliance.get("gaps", [])[:10]

        # Extract correlations
        correlations = scan_data.get("correlations", {})
        if correlations:
            summary["correlations"] = correlations.get("findings", [])[:10]
            summary["insights"] = correlations.get("insights", [])[:5]

        # Extract executive report if present
        exec_report = scan_data.get("executive_report", {})
        if exec_report:
            summary["executive_summary"] = exec_report.get("executive_summary", {})
            summary["recommendations"] = exec_report.get("recommendations", [])[:5]

        # Domain profile
        domain = scan_data.get("domain_profile", {})
        if domain:
            summary["domain_info"] = {
                "dns": domain.get("dns", {}),
                "registrar": domain.get("registrar", "Unknown"),
            }

        # Tech stack
        tech = scan_data.get("tech_stack", {})
        if tech:
            summary["technologies"] = tech.get("technologies", [])[:10]

        return summary


# Convenience functions for module integration
def ai_analyze(ctx, params: Optional[Dict[str, Any]] = None):
    """Module wrapper for AI analysis."""
    from redops.core.context import Context

    try:
        assistant = AIAssistant()
        analysis = assistant.analyze_findings(ctx.data)
        ctx.add("ai_analysis", {
            "analysis": analysis,
            "provider": assistant.provider,
            "model": assistant.model,
        })
    except Exception as e:
        ctx.log(f"AI analysis failed: {e}", level="ERROR")

    return ctx


def ai_summarize(ctx, params: Optional[Dict[str, Any]] = None):
    """Module wrapper for AI summarization."""
    from redops.core.context import Context

    try:
        assistant = AIAssistant()
        summary = assistant.summarize(ctx.data)
        ctx.add("ai_summary", {
            "summary": summary,
            "provider": assistant.provider,
            "model": assistant.model,
        })
    except Exception as e:
        ctx.log(f"AI summarization failed: {e}", level="ERROR")

    return ctx


def ai_recommend(ctx, params: Optional[Dict[str, Any]] = None):
    """Module wrapper for AI recommendations."""
    from redops.core.context import Context

    try:
        assistant = AIAssistant()
        recommendations = assistant.suggest_remediations(ctx.data)
        ctx.add("ai_recommendations", {
            "recommendations": recommendations,
            "provider": assistant.provider,
            "model": assistant.model,
        })
    except Exception as e:
        ctx.log(f"AI recommendations failed: {e}", level="ERROR")

    return ctx
