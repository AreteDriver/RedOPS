"""Tests for STIX/TAXII export module."""

import json
import pytest
from unittest.mock import MagicMock, patch

from redops.modules.intel.stix_export import (
    STIX_VERSION,
    generate_stix_id,
    stix_timestamp,
    STIXObject,
    Indicator,
    ThreatActor,
    AttackPattern,
    Vulnerability,
    Infrastructure,
    Relationship,
    Bundle,
    STIXExporter,
    export_to_stix,
)


class TestGenerateStixId:
    """Tests for generate_stix_id function."""

    def test_format(self):
        """Test ID format."""
        id = generate_stix_id("indicator")
        assert id.startswith("indicator--")
        assert len(id) == len("indicator--") + 36  # UUID length

    def test_unique(self):
        """Test IDs are unique."""
        ids = [generate_stix_id("indicator") for _ in range(100)]
        assert len(set(ids)) == 100

    def test_different_types(self):
        """Test different object types."""
        ind_id = generate_stix_id("indicator")
        vuln_id = generate_stix_id("vulnerability")
        assert ind_id.startswith("indicator--")
        assert vuln_id.startswith("vulnerability--")


class TestStixTimestamp:
    """Tests for stix_timestamp function."""

    def test_format(self):
        """Test timestamp format."""
        ts = stix_timestamp()
        assert ts.endswith("Z")
        assert "T" in ts
        assert len(ts) == 24  # YYYY-MM-DDTHH:MM:SS.mmmZ

    def test_iso_format(self):
        """Test timestamp is valid ISO format."""
        from datetime import datetime
        ts = stix_timestamp()
        # Should not raise
        datetime.fromisoformat(ts.replace("Z", "+00:00"))


class TestSTIXObject:
    """Tests for STIXObject base class."""

    def test_auto_id(self):
        """Test automatic ID generation."""
        obj = STIXObject(type="test")
        assert obj.id.startswith("test--")

    def test_custom_id(self):
        """Test custom ID."""
        obj = STIXObject(type="test", id="test--custom-id")
        assert obj.id == "test--custom-id"

    def test_spec_version(self):
        """Test spec version."""
        obj = STIXObject(type="test")
        assert obj.spec_version == STIX_VERSION

    def test_to_dict(self):
        """Test conversion to dictionary."""
        obj = STIXObject(type="test")
        d = obj.to_dict()
        assert d["type"] == "test"
        assert "id" in d
        assert "created" in d
        assert "modified" in d

    def test_to_dict_no_none(self):
        """Test None values are excluded."""
        obj = STIXObject(type="test")
        d = obj.to_dict()
        assert None not in d.values()


class TestIndicator:
    """Tests for Indicator class."""

    def test_type(self):
        """Test indicator type."""
        ind = Indicator()
        assert ind.type == "indicator"

    def test_with_pattern(self):
        """Test indicator with pattern."""
        ind = Indicator(
            name="Test IP",
            pattern="[ipv4-addr:value = '192.168.1.1']",
            pattern_type="stix"
        )
        assert ind.pattern == "[ipv4-addr:value = '192.168.1.1']"

    def test_indicator_types(self):
        """Test indicator types list."""
        ind = Indicator(
            name="Malware",
            indicator_types=["malicious-activity", "compromised"]
        )
        assert "malicious-activity" in ind.indicator_types

    def test_to_dict(self):
        """Test indicator to_dict includes all fields."""
        ind = Indicator(
            name="Test",
            description="Test indicator",
            pattern="[domain-name:value = 'evil.com']",
            confidence=85
        )
        d = ind.to_dict()
        assert d["name"] == "Test"
        assert d["confidence"] == 85


class TestThreatActor:
    """Tests for ThreatActor class."""

    def test_type(self):
        """Test threat actor type."""
        ta = ThreatActor()
        assert ta.type == "threat-actor"

    def test_with_details(self):
        """Test threat actor with details."""
        ta = ThreatActor(
            name="APT28",
            aliases=["Fancy Bear", "Sofacy"],
            threat_actor_types=["nation-state"],
            sophistication="advanced",
            primary_motivation="ideology"
        )
        assert ta.name == "APT28"
        assert "Fancy Bear" in ta.aliases
        assert ta.sophistication == "advanced"


class TestAttackPattern:
    """Tests for AttackPattern class."""

    def test_type(self):
        """Test attack pattern type."""
        ap = AttackPattern()
        assert ap.type == "attack-pattern"

    def test_with_mitre(self):
        """Test attack pattern with MITRE reference."""
        ap = AttackPattern(
            name="Spearphishing Attachment",
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": "T1566.001"
            }]
        )
        assert ap.name == "Spearphishing Attachment"
        assert len(ap.external_references) == 1


class TestVulnerability:
    """Tests for Vulnerability class."""

    def test_type(self):
        """Test vulnerability type."""
        vuln = Vulnerability()
        assert vuln.type == "vulnerability"

    def test_with_cve(self):
        """Test vulnerability with CVE reference."""
        vuln = Vulnerability(
            name="CVE-2021-44228",
            description="Log4j RCE",
            external_references=[{
                "source_name": "cve",
                "external_id": "CVE-2021-44228"
            }]
        )
        assert vuln.name == "CVE-2021-44228"


class TestInfrastructure:
    """Tests for Infrastructure class."""

    def test_type(self):
        """Test infrastructure type."""
        infra = Infrastructure()
        assert infra.type == "infrastructure"

    def test_with_details(self):
        """Test infrastructure with details."""
        infra = Infrastructure(
            name="C2 Server",
            infrastructure_types=["command-and-control"],
            aliases=["Cobalt Strike"]
        )
        assert "command-and-control" in infra.infrastructure_types


class TestRelationship:
    """Tests for Relationship class."""

    def test_type(self):
        """Test relationship type."""
        rel = Relationship()
        assert rel.type == "relationship"

    def test_with_refs(self):
        """Test relationship with references."""
        rel = Relationship(
            relationship_type="indicates",
            source_ref="indicator--123",
            target_ref="malware--456"
        )
        assert rel.relationship_type == "indicates"
        assert rel.source_ref == "indicator--123"


class TestBundle:
    """Tests for Bundle class."""

    def test_type(self):
        """Test bundle type."""
        bundle = Bundle()
        assert bundle.type == "bundle"

    def test_id(self):
        """Test bundle ID."""
        bundle = Bundle()
        assert bundle.id.startswith("bundle--")

    def test_add_object(self):
        """Test adding objects."""
        bundle = Bundle()
        ind = Indicator(name="Test")
        bundle.add(ind)
        assert len(bundle.objects) == 1

    def test_to_dict(self):
        """Test bundle to_dict."""
        bundle = Bundle()
        bundle.add(Indicator(name="Test"))
        d = bundle.to_dict()
        assert d["type"] == "bundle"
        assert len(d["objects"]) == 1

    def test_to_json(self):
        """Test bundle to_json."""
        bundle = Bundle()
        bundle.add(Indicator(name="Test"))
        j = bundle.to_json()
        parsed = json.loads(j)
        assert parsed["type"] == "bundle"


class TestSTIXExporter:
    """Tests for STIXExporter class."""

    def test_init(self):
        """Test exporter initialization."""
        exporter = STIXExporter()
        assert exporter.identity_name == "RedOPS Security Scanner"
        assert exporter.identity_id.startswith("identity--")

    def test_init_custom_identity(self):
        """Test exporter with custom identity."""
        exporter = STIXExporter(identity_name="Custom Scanner")
        assert exporter.identity_name == "Custom Scanner"

    def test_export_empty(self):
        """Test exporting empty data."""
        exporter = STIXExporter()
        bundle = exporter.export({})
        # Should have identity at minimum
        assert len(bundle.objects) >= 1

    def test_export_with_iocs(self):
        """Test exporting IOCs."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [
                    {"type": "ip", "value": "192.168.1.1"},
                    {"type": "domain", "value": "evil.com"},
                    {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                ]
            }
        }
        bundle = exporter.export(data)
        # Identity + 3 indicators
        assert len(bundle.objects) >= 4

    def test_export_ip_patterns(self):
        """Test IP IOC pattern generation."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [
                    {"type": "ip", "value": "10.0.0.1"},
                    {"type": "ipv4-addr", "value": "10.0.0.2"},
                    {"type": "ipv6-addr", "value": "::1"},
                ]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "ipv4-addr:value" in json_str
        assert "ipv6-addr:value" in json_str

    def test_export_domain_pattern(self):
        """Test domain IOC pattern."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [{"type": "domain", "value": "test.com"}]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "domain-name:value" in json_str

    def test_export_url_pattern(self):
        """Test URL IOC pattern."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [{"type": "url", "value": "http://evil.com/malware"}]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "url:value" in json_str

    def test_export_hash_patterns(self):
        """Test hash IOC pattern detection."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [
                    {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"},  # MD5
                    {"type": "hash", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},  # SHA-1
                    {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},  # SHA-256
                ]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "MD5" in json_str
        assert "SHA-1" in json_str
        assert "SHA-256" in json_str

    def test_export_email_pattern(self):
        """Test email IOC pattern."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [{"type": "email", "value": "bad@evil.com"}]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "email-addr:value" in json_str

    def test_export_unknown_ioc_type(self):
        """Test unknown IOC type uses artifact."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [{"type": "custom", "value": "some-value"}]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "artifact:payload_bin" in json_str

    def test_export_ioc_without_value(self):
        """Test IOC without value is skipped."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "iocs": [{"type": "ip", "value": ""}]
            }
        }
        bundle = exporter.export(data)
        # Should only have identity, no indicator
        assert len(bundle.objects) == 1

    def test_export_with_findings(self):
        """Test exporting vulnerability findings."""
        exporter = STIXExporter()
        data = {
            "findings": [
                {"title": "CVE-2021-44228", "cve": "CVE-2021-44228", "description": "Log4j"},
                {"title": "Other finding"},  # No CVE, should be skipped
            ]
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "CVE-2021-44228" in json_str

    def test_export_with_mitre(self):
        """Test exporting MITRE techniques."""
        exporter = STIXExporter()
        data = {
            "threat_intel": {
                "mitre_techniques": [
                    {
                        "technique_id": "T1566.001",
                        "name": "Spearphishing Attachment",
                        "tactic": "Initial Access"
                    }
                ]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "T1566.001" in json_str
        assert "mitre-attack" in json_str

    def test_export_with_infrastructure(self):
        """Test exporting infrastructure."""
        exporter = STIXExporter()
        data = {
            "target": "example.com",
            "infrastructure": {
                "cloud_provider": "AWS",
                "cdn": "Cloudflare"
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "infrastructure" in json_str
        assert "hosting" in json_str

    def test_export_with_exposures(self):
        """Test exporting exposures."""
        exporter = STIXExporter()
        data = {
            "exposure_scan": {
                "exposures": [
                    {"type": "open_port", "value": "22", "severity": "high"},
                    {"type": "exposed_domain", "value": "test.example.com"},
                    {"type": "exposed_email", "value": "admin@example.com"},
                ]
            }
        }
        bundle = exporter.export(data)
        json_str = bundle.to_json()
        assert "network-traffic:dst_port" in json_str
        assert "domain-name:value" in json_str
        assert "email-addr:value" in json_str

    def test_export_exposure_unknown_type(self):
        """Test unknown exposure type is skipped."""
        exporter = STIXExporter()
        data = {
            "exposure_scan": {
                "exposures": [
                    {"type": "unknown", "value": "something"}
                ]
            }
        }
        bundle = exporter.export(data)
        # Only identity
        assert len(bundle.objects) == 1


class TestExportToStix:
    """Tests for export_to_stix pipeline function."""

    def test_basic_export(self):
        """Test basic pipeline export."""
        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        result = export_to_stix(ctx)

        ctx.add.assert_called()
        ctx.log.assert_called()
        assert result == ctx

    def test_export_with_output_path(self, tmp_path):
        """Test export with output file."""
        output_file = tmp_path / "stix_bundle.json"

        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        params = {"output_path": str(output_file)}
        export_to_stix(ctx, params)

        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert data["type"] == "bundle"

    def test_export_custom_identity(self):
        """Test export with custom identity."""
        ctx = MagicMock()
        ctx.data = {}

        params = {"identity_name": "Custom Tool"}
        export_to_stix(ctx, params)

        ctx.add.assert_called()

    def test_export_error_handling(self):
        """Test export handles errors."""
        ctx = MagicMock()
        ctx.data = None  # This will cause an error

        # Should not raise
        result = export_to_stix(ctx)

        # Should log error
        assert any("ERROR" in str(call) for call in ctx.log.call_args_list)
        assert result == ctx
