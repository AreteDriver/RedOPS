"""
Sample Enricher Plugin for RedOPS.

This example demonstrates how to create an enricher plugin that
adds additional data to findings or context.

To use this plugin:
1. Copy to ~/.config/redops/plugins/
2. The enricher runs after modules to add more context
"""

from redops.core.plugin_system import (
    BasePlugin,
    PluginMetadata,
    PluginType,
    PipelineContext,
)


class SampleIPEnricher(BasePlugin):
    """
    Sample IP address enricher.

    Demonstrates:
    - Enricher plugin structure
    - Reading from context
    - Adding enriched data
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_ip_enricher",
            version="1.0.0",
            description="Sample IP enricher plugin (demo only)",
            author="RedOPS Examples",
            plugin_type=PluginType.ENRICHER,
            tags=["enricher", "ip", "sample"],
        )

    def initialize(self, config: dict | None = None) -> None:
        """Initialize enricher."""
        super().initialize(config)
        # Mock database of known IPs
        self.known_ips = {
            "8.8.8.8": {"owner": "Google", "service": "DNS", "reputation": "good"},
            "1.1.1.1": {"owner": "Cloudflare", "service": "DNS", "reputation": "good"},
            "192.168.1.1": {
                "owner": "Private",
                "service": "Router",
                "reputation": "internal",
            },
        }

    def enrich(self, ctx: PipelineContext, data_key: str = None) -> dict:
        """
        Enrich IP addresses found in context.

        Args:
            ctx: Pipeline context with collected data
            data_key: Specific key to enrich (optional)

        Returns:
            Enrichment results
        """
        enrichments = []

        # Look for IP addresses in context data
        for key, value in ctx.data.items():
            if not isinstance(value, dict):
                continue

            # Check for IPs in various fields
            ips = self._extract_ips(value)
            for ip in ips:
                enriched = self._enrich_ip(ip)
                if enriched:
                    enrichments.append(enriched)

        result = {
            "enriched_count": len(enrichments),
            "enrichments": enrichments,
        }

        ctx.add("ip_enrichments", result)
        ctx.log(f"[IPEnricher] Enriched {len(enrichments)} IP addresses", level="INFO")

        return result

    def _extract_ips(self, data: dict, ips: list = None) -> list:
        """Recursively extract IP addresses from data."""
        if ips is None:
            ips = []

        for key, value in data.items():
            if isinstance(value, str) and self._looks_like_ip(value):
                ips.append(value)
            elif isinstance(value, dict):
                self._extract_ips(value, ips)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and self._looks_like_ip(item):
                        ips.append(item)
                    elif isinstance(item, dict):
                        self._extract_ips(item, ips)

        return list(set(ips))  # Deduplicate

    def _looks_like_ip(self, value: str) -> bool:
        """Check if value looks like an IP address."""
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _enrich_ip(self, ip: str) -> dict | None:
        """Get enrichment data for an IP."""
        if ip in self.known_ips:
            return {
                "ip": ip,
                "source": "sample_database",
                **self.known_ips[ip],
            }
        return None


class SampleDomainEnricher(BasePlugin):
    """
    Sample domain enricher that adds risk indicators.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_domain_enricher",
            version="1.0.0",
            description="Sample domain risk enricher (demo only)",
            author="RedOPS Examples",
            plugin_type=PluginType.ENRICHER,
            tags=["enricher", "domain", "risk", "sample"],
        )

    def initialize(self, config: dict | None = None) -> None:
        """Initialize with risk indicators."""
        super().initialize(config)
        # Mock risk indicators
        self.high_risk_tlds = [".xyz", ".top", ".click", ".loan"]
        self.suspicious_keywords = ["free", "win", "prize", "urgent"]

    def enrich(self, ctx: PipelineContext, data_key: str = None) -> dict:
        """
        Add risk indicators to domain.

        Args:
            ctx: Pipeline context

        Returns:
            Risk assessment
        """
        target = ctx.target or ""

        risk_factors = []
        risk_score = 0

        # Check TLD
        for tld in self.high_risk_tlds:
            if target.endswith(tld):
                risk_factors.append(f"High-risk TLD: {tld}")
                risk_score += 30

        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword in target.lower():
                risk_factors.append(f"Suspicious keyword: {keyword}")
                risk_score += 20

        # Check domain age (mock)
        domain_info = ctx.get("domain_info", {})
        if domain_info.get("age_days", 365) < 30:
            risk_factors.append("Newly registered domain")
            risk_score += 40

        result = {
            "target": target,
            "risk_score": min(risk_score, 100),  # Cap at 100
            "risk_level": self._score_to_level(risk_score),
            "risk_factors": risk_factors,
            "note": "This is sample data - implement real risk assessment",
        }

        ctx.add("domain_risk", result)
        ctx.log(f"[DomainEnricher] Risk score for {target}: {risk_score}", level="INFO")

        return result

    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to level."""
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        elif score > 0:
            return "low"
        return "none"


__all__ = ["SampleIPEnricher", "SampleDomainEnricher"]
