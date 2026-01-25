"""Tests for compliance/compliance_map module."""

from redops.modules.compliance.compliance_map import (
    ComplianceFramework,
    ControlStatus,
    ControlPriority,
    ComplianceControl,
    ControlAssessment,
    ComplianceReport,
    PCI_DSS_CONTROLS,
    HIPAA_CONTROLS,
    SOC2_CONTROLS,
    NIST_CSF_CONTROLS,
    ALL_CONTROLS,
    FINDING_KEYWORD_MAP,
    assess_compliance,
    collect_findings_from_context,
    assess_framework,
    get_controls_for_framework,
    map_findings_to_controls,
    assess_control,
    generate_control_remediation,
    identify_cross_framework_gaps,
    generate_priority_remediations,
    calculate_overall_posture,
    get_framework,
    get_all_frameworks,
    get_control,
    get_related_controls,
    get_controls_by_category,
    get_controls_by_priority,
    map_control_across_frameworks,
    get_framework_categories,
    calculate_category_score,
    export_gap_analysis,
)
from redops.core.context import Context


class TestComplianceFramework:
    """Tests for ComplianceFramework enum."""

    def test_framework_values(self):
        """Test all framework values exist."""
        assert ComplianceFramework.PCI_DSS.value == "pci_dss"
        assert ComplianceFramework.HIPAA.value == "hipaa"
        assert ComplianceFramework.SOC2.value == "soc2"
        assert ComplianceFramework.NIST_CSF.value == "nist_csf"
        assert ComplianceFramework.ISO_27001.value == "iso_27001"
        assert ComplianceFramework.GDPR.value == "gdpr"

    def test_framework_count(self):
        """Test number of frameworks."""
        assert len(ComplianceFramework) >= 6


class TestControlStatus:
    """Tests for ControlStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert ControlStatus.COMPLIANT.value == "compliant"
        assert ControlStatus.PARTIAL.value == "partial"
        assert ControlStatus.NON_COMPLIANT.value == "non_compliant"
        assert ControlStatus.NOT_APPLICABLE.value == "not_applicable"
        assert ControlStatus.NOT_ASSESSED.value == "not_assessed"


class TestControlPriority:
    """Tests for ControlPriority enum."""

    def test_priority_values(self):
        """Test all priority values exist."""
        assert ControlPriority.CRITICAL.value == "critical"
        assert ControlPriority.HIGH.value == "high"
        assert ControlPriority.MEDIUM.value == "medium"
        assert ControlPriority.LOW.value == "low"


class TestComplianceControl:
    """Tests for ComplianceControl dataclass."""

    def test_basic_creation(self):
        """Test basic control creation."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test Control",
            description="Test description",
            category="Test Category",
        )
        assert control.id == "TEST.1"
        assert control.framework == ComplianceFramework.PCI_DSS
        assert control.priority == ControlPriority.MEDIUM

    def test_full_creation(self):
        """Test control with all fields."""
        control = ComplianceControl(
            id="TEST.2",
            framework=ComplianceFramework.HIPAA,
            title="Full Control",
            description="Full description",
            category="Security",
            priority=ControlPriority.CRITICAL,
            related_controls=["PCI.8.3", "NIST.PR.AC-1"],
            evidence_types=["config", "logs"],
            automation_possible=True,
        )
        assert control.priority == ControlPriority.CRITICAL
        assert len(control.related_controls) == 2
        assert "config" in control.evidence_types

    def test_to_dict(self):
        """Test control to_dict method."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.SOC2,
            title="Test",
            description="Desc",
            category="Cat",
            priority=ControlPriority.HIGH,
        )
        result = control.to_dict()

        assert result["id"] == "TEST.1"
        assert result["framework"] == "soc2"
        assert result["priority"] == "high"


class TestControlAssessment:
    """Tests for ControlAssessment dataclass."""

    def test_basic_creation(self):
        """Test basic assessment creation."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Cat",
        )
        assessment = ControlAssessment(
            control=control,
            status=ControlStatus.COMPLIANT,
        )
        assert assessment.status == ControlStatus.COMPLIANT
        assert assessment.findings == []

    def test_full_creation(self):
        """Test assessment with all fields."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Cat",
        )
        assessment = ControlAssessment(
            control=control,
            status=ControlStatus.NON_COMPLIANT,
            findings=["Finding 1", "Finding 2"],
            evidence=["Evidence 1"],
            gaps=["Gap 1"],
            remediation=["Fix 1"],
            notes="Test notes",
        )
        assert len(assessment.findings) == 2
        assert len(assessment.gaps) == 1

    def test_to_dict(self):
        """Test assessment to_dict method."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test Control",
            description="Desc",
            category="Cat",
        )
        assessment = ControlAssessment(
            control=control,
            status=ControlStatus.PARTIAL,
        )
        result = assessment.to_dict()

        assert result["control_id"] == "TEST.1"
        assert result["status"] == "partial"
        assert result["title"] == "Test Control"


class TestComplianceReport:
    """Tests for ComplianceReport dataclass."""

    def test_basic_creation(self):
        """Test basic report creation."""
        report = ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            target="example.com",
        )
        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.overall_score == 0.0

    def test_to_dict(self):
        """Test report to_dict method."""
        report = ComplianceReport(
            framework=ComplianceFramework.HIPAA,
            target="test.com",
            overall_score=75.5,
            compliant_count=10,
            non_compliant_count=3,
        )
        result = report.to_dict()

        assert result["framework"] == "hipaa"
        assert result["overall_score"] == 75.5
        assert result["compliant_count"] == 10


class TestPCIDSSControls:
    """Tests for PCI-DSS controls database."""

    def test_controls_exist(self):
        """Test that controls exist."""
        assert len(PCI_DSS_CONTROLS) >= 10

    def test_required_controls(self):
        """Test required controls are present."""
        assert "1.1" in PCI_DSS_CONTROLS
        assert "8.3" in PCI_DSS_CONTROLS
        assert "11.3" in PCI_DSS_CONTROLS

    def test_control_structure(self):
        """Test control structure is valid."""
        for control_id, control in PCI_DSS_CONTROLS.items():
            assert control.id == control_id
            assert control.framework == ComplianceFramework.PCI_DSS
            assert control.title
            assert control.description
            assert control.category

    def test_critical_controls_marked(self):
        """Test critical controls are properly marked."""
        critical_controls = [
            c
            for c in PCI_DSS_CONTROLS.values()
            if c.priority == ControlPriority.CRITICAL
        ]
        assert len(critical_controls) >= 3


class TestHIPAAControls:
    """Tests for HIPAA controls database."""

    def test_controls_exist(self):
        """Test that controls exist."""
        assert len(HIPAA_CONTROLS) >= 10

    def test_required_controls(self):
        """Test required controls are present."""
        assert "164.308(a)(1)" in HIPAA_CONTROLS
        assert "164.312(a)(1)" in HIPAA_CONTROLS
        assert "164.312(e)(1)" in HIPAA_CONTROLS

    def test_safeguard_categories(self):
        """Test safeguard categories are represented."""
        categories = set(c.category for c in HIPAA_CONTROLS.values())
        assert "Administrative Safeguards" in categories
        assert "Technical Safeguards" in categories
        assert "Physical Safeguards" in categories


class TestSOC2Controls:
    """Tests for SOC 2 controls database."""

    def test_controls_exist(self):
        """Test that controls exist."""
        assert len(SOC2_CONTROLS) >= 10

    def test_trust_service_criteria(self):
        """Test trust service criteria are represented."""
        categories = set(c.category for c in SOC2_CONTROLS.values())
        assert "Security" in categories
        assert "Availability" in categories
        assert "Confidentiality" in categories

    def test_cc_controls_present(self):
        """Test common criteria controls are present."""
        assert "CC6.1" in SOC2_CONTROLS
        assert "CC6.6" in SOC2_CONTROLS


class TestNISTCSFControls:
    """Tests for NIST CSF controls database."""

    def test_controls_exist(self):
        """Test that controls exist."""
        assert len(NIST_CSF_CONTROLS) >= 10

    def test_csf_functions(self):
        """Test CSF functions are represented."""
        categories = set(c.category for c in NIST_CSF_CONTROLS.values())
        assert "Identify" in categories
        assert "Protect" in categories
        assert "Detect" in categories
        assert "Respond" in categories
        assert "Recover" in categories


class TestAllControls:
    """Tests for combined controls dictionary."""

    def test_all_frameworks_included(self):
        """Test all frameworks have controls."""
        prefixes = set(k.split(".")[0] for k in ALL_CONTROLS.keys())
        assert "PCI" in prefixes
        assert "HIPAA" in prefixes
        assert "SOC2" in prefixes
        assert "NIST" in prefixes

    def test_control_count(self):
        """Test total control count."""
        expected = (
            len(PCI_DSS_CONTROLS)
            + len(HIPAA_CONTROLS)
            + len(SOC2_CONTROLS)
            + len(NIST_CSF_CONTROLS)
        )
        assert len(ALL_CONTROLS) == expected


class TestFindingKeywordMap:
    """Tests for finding keyword mapping."""

    def test_keyword_categories(self):
        """Test keyword categories are present."""
        assert "password" in FINDING_KEYWORD_MAP
        assert "encryption" in FINDING_KEYWORD_MAP
        assert "vulnerability" in FINDING_KEYWORD_MAP
        assert "firewall" in FINDING_KEYWORD_MAP

    def test_cross_framework_mapping(self):
        """Test keywords map to multiple frameworks."""
        password_controls = FINDING_KEYWORD_MAP["password"]
        frameworks = set(c.split(".")[0] for c in password_controls)
        assert len(frameworks) >= 2


class TestAssessCompliance:
    """Tests for assess_compliance function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        result = assess_compliance(ctx)

        assert "compliance_assessment" in result.data
        assessment = result.get("compliance_assessment")
        assert assessment["target"] == "example.com"
        assert len(assessment["reports"]) >= 1

    def test_no_target_warning(self):
        """Test warning when no target."""
        ctx = Context(target="")
        result = assess_compliance(ctx)

        warnings = result.get_logs(level="WARNING")
        assert len(warnings) >= 1

    def test_single_framework(self):
        """Test assessment with single framework."""
        ctx = Context(target="example.com")
        result = assess_compliance(ctx, {"frameworks": ["pci_dss"]})

        assessment = result.get("compliance_assessment")
        assert len(assessment["reports"]) == 1
        assert assessment["reports"][0]["framework"] == "pci_dss"

    def test_multiple_frameworks(self):
        """Test assessment with multiple frameworks."""
        ctx = Context(target="example.com")
        result = assess_compliance(ctx, {"frameworks": ["pci_dss", "hipaa", "soc2"]})

        assessment = result.get("compliance_assessment")
        assert len(assessment["reports"]) == 3

    def test_with_findings(self):
        """Test assessment with findings."""
        ctx = Context(target="example.com")
        ctx.add(
            "findings",
            [
                {"title": "Weak Password Policy", "severity": "high"},
                {"title": "Missing Encryption", "severity": "critical"},
            ],
        )

        result = assess_compliance(ctx)
        assessment = result.get("compliance_assessment")

        # Should have gaps identified
        total_gaps = sum(r["non_compliant_count"] for r in assessment["reports"])
        assert (
            total_gaps > 0 or sum(r["partial_count"] for r in assessment["reports"]) > 0
        )


class TestCollectFindingsFromContext:
    """Tests for collect_findings_from_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        findings = collect_findings_from_context(ctx)
        assert findings == []

    def test_findings_key(self):
        """Test collecting from findings key."""
        ctx = Context(target="example.com")
        ctx.add(
            "findings",
            [
                {"title": "Finding 1"},
                {"title": "Finding 2"},
            ],
        )

        findings = collect_findings_from_context(ctx)
        assert len(findings) == 2

    def test_finding_n_keys(self):
        """Test collecting from finding_N keys."""
        ctx = Context(target="example.com")
        ctx.add("finding_0", {"title": "Finding 0"})
        ctx.add("finding_1", {"title": "Finding 1"})

        findings = collect_findings_from_context(ctx)
        assert len(findings) == 2

    def test_exposure_scan(self):
        """Test collecting from exposure_scan."""
        ctx = Context(target="example.com")
        ctx.add(
            "exposure_scan",
            {
                "findings": [
                    {"title": "Exposed Config"},
                ]
            },
        )

        findings = collect_findings_from_context(ctx)
        assert len(findings) == 1


class TestAssessFramework:
    """Tests for assess_framework function."""

    def test_pci_dss_assessment(self):
        """Test PCI-DSS assessment."""
        findings = [
            {"title": "Password Policy Weak", "severity": "high"},
        ]
        report = assess_framework(ComplianceFramework.PCI_DSS, findings, "example.com")

        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.target == "example.com"
        assert len(report.assessments) > 0

    def test_hipaa_assessment(self):
        """Test HIPAA assessment."""
        findings = []
        report = assess_framework(ComplianceFramework.HIPAA, findings, "example.com")

        assert report.framework == ComplianceFramework.HIPAA
        assert len(report.assessments) == len(HIPAA_CONTROLS)

    def test_score_calculation(self):
        """Test score calculation."""
        findings = []  # No findings = not assessed
        report = assess_framework(ComplianceFramework.PCI_DSS, findings, "example.com")

        # With no findings, most controls are not_assessed
        assert report.not_assessed_count >= report.compliant_count


class TestGetControlsForFramework:
    """Tests for get_controls_for_framework function."""

    def test_pci_dss(self):
        """Test getting PCI-DSS controls."""
        controls = get_controls_for_framework(ComplianceFramework.PCI_DSS)
        assert len(controls) == len(PCI_DSS_CONTROLS)
        assert all(k.startswith("PCI.") for k in controls.keys())

    def test_hipaa(self):
        """Test getting HIPAA controls."""
        controls = get_controls_for_framework(ComplianceFramework.HIPAA)
        assert len(controls) == len(HIPAA_CONTROLS)
        assert all(k.startswith("HIPAA.") for k in controls.keys())

    def test_soc2(self):
        """Test getting SOC 2 controls."""
        controls = get_controls_for_framework(ComplianceFramework.SOC2)
        assert len(controls) == len(SOC2_CONTROLS)

    def test_unknown_framework(self):
        """Test with unsupported framework."""
        controls = get_controls_for_framework(ComplianceFramework.ISO_27001)
        assert controls == {}


class TestMapFindingsToControls:
    """Tests for map_findings_to_controls function."""

    def test_password_finding(self):
        """Test password finding mapping."""
        findings = [
            {"title": "Weak Password Policy", "description": "Passwords too short"},
        ]
        mapping = map_findings_to_controls(findings, ComplianceFramework.PCI_DSS)

        assert "PCI.8.3" in mapping

    def test_encryption_finding(self):
        """Test encryption finding mapping."""
        findings = [
            {"title": "Missing TLS", "description": "No encryption in transit"},
        ]
        mapping = map_findings_to_controls(findings, ComplianceFramework.PCI_DSS)

        assert "PCI.4.1" in mapping

    def test_vulnerability_finding(self):
        """Test vulnerability finding mapping."""
        findings = [
            {"title": "CVE-2021-12345", "description": "Critical vulnerability found"},
        ]
        mapping = map_findings_to_controls(findings, ComplianceFramework.PCI_DSS)

        assert "PCI.6.3" in mapping or "PCI.11.3" in mapping


class TestAssessControl:
    """Tests for assess_control function."""

    def test_no_findings(self):
        """Test control with no findings."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Cat",
        )
        assessment = assess_control(control, [], [])

        assert assessment.status == ControlStatus.NOT_ASSESSED

    def test_critical_finding(self):
        """Test control with critical finding."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Cat",
        )
        findings = [{"title": "Critical Issue", "severity": "critical"}]
        assessment = assess_control(control, findings, findings)

        assert assessment.status == ControlStatus.NON_COMPLIANT

    def test_medium_finding(self):
        """Test control with medium finding."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Cat",
        )
        findings = [{"title": "Medium Issue", "severity": "medium"}]
        assessment = assess_control(control, findings, findings)

        assert assessment.status == ControlStatus.PARTIAL


class TestGenerateControlRemediation:
    """Tests for generate_control_remediation function."""

    def test_authentication_remediation(self):
        """Test authentication-related remediation."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Authentication",
        )
        remediation = generate_control_remediation(control, [])

        assert any("MFA" in r or "password" in r.lower() for r in remediation)

    def test_encryption_remediation(self):
        """Test encryption-related remediation."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Encryption",
        )
        remediation = generate_control_remediation(control, [])

        assert any("TLS" in r or "encryption" in r.lower() for r in remediation)

    def test_vulnerability_remediation(self):
        """Test vulnerability-related remediation."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="Desc",
            category="Vulnerability Management",
        )
        remediation = generate_control_remediation(control, [])

        assert any("scan" in r.lower() or "patch" in r.lower() for r in remediation)


class TestIdentifyCrossFrameworkGaps:
    """Tests for identify_cross_framework_gaps function."""

    def test_no_gaps(self):
        """Test with no gaps."""
        gaps = identify_cross_framework_gaps([])
        assert gaps == []

    def test_cross_framework_gap(self):
        """Test identifying cross-framework gaps."""
        # Use a shared related control ID that both controls reference
        shared_control_id = "SHARED.AUTH.1"

        control1 = ComplianceControl(
            id="PCI.8.3",
            framework=ComplianceFramework.PCI_DSS,
            title="Strong Auth",
            description="",
            category="Auth",
            related_controls=[shared_control_id],
        )
        control2 = ComplianceControl(
            id="HIPAA.164.312(d)",
            framework=ComplianceFramework.HIPAA,
            title="Person Auth",
            description="",
            category="Tech",
            related_controls=[shared_control_id],
        )

        assessments = [
            ControlAssessment(control=control1, status=ControlStatus.NON_COMPLIANT),
            ControlAssessment(control=control2, status=ControlStatus.NON_COMPLIANT),
        ]

        gaps = identify_cross_framework_gaps(assessments)

        # Should find the shared control affecting both frameworks
        assert len(gaps) >= 1
        assert gaps[0]["related_control"] == shared_control_id
        assert len(gaps[0]["affected_frameworks"]) == 2


class TestGeneratePriorityRemediations:
    """Tests for generate_priority_remediations function."""

    def test_no_assessments(self):
        """Test with no assessments."""
        remediations = generate_priority_remediations([])
        assert remediations == []

    def test_priority_ordering(self):
        """Test remediation priority ordering."""
        critical_control = ComplianceControl(
            id="CRIT.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Critical",
            description="",
            category="",
            priority=ControlPriority.CRITICAL,
        )
        low_control = ComplianceControl(
            id="LOW.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Low",
            description="",
            category="",
            priority=ControlPriority.LOW,
        )

        assessments = [
            ControlAssessment(control=low_control, status=ControlStatus.NON_COMPLIANT),
            ControlAssessment(
                control=critical_control, status=ControlStatus.NON_COMPLIANT
            ),
        ]

        remediations = generate_priority_remediations(assessments)

        # Critical should come first
        assert remediations[0]["priority"] == "critical"


class TestCalculateOverallPosture:
    """Tests for calculate_overall_posture function."""

    def test_no_reports(self):
        """Test with no reports."""
        posture = calculate_overall_posture([])
        assert posture["overall_score"] == 0
        assert posture["status"] == "not_assessed"

    def test_strong_posture(self):
        """Test strong compliance posture."""
        reports = [
            {
                "framework": "pci_dss",
                "overall_score": 95,
                "non_compliant_count": 1,
                "partial_count": 2,
            },
            {
                "framework": "hipaa",
                "overall_score": 92,
                "non_compliant_count": 1,
                "partial_count": 1,
            },
        ]
        posture = calculate_overall_posture(reports)

        assert posture["overall_score"] >= 90
        assert posture["status"] == "strong"

    def test_weak_posture(self):
        """Test weak compliance posture."""
        reports = [
            {
                "framework": "pci_dss",
                "overall_score": 40,
                "non_compliant_count": 10,
                "partial_count": 5,
            },
        ]
        posture = calculate_overall_posture(reports)

        assert posture["overall_score"] < 50
        assert posture["status"] == "critical"


class TestGetFramework:
    """Tests for get_framework function."""

    def test_valid_framework(self):
        """Test getting valid framework."""
        assert get_framework("pci_dss") == ComplianceFramework.PCI_DSS
        assert get_framework("hipaa") == ComplianceFramework.HIPAA

    def test_normalized_names(self):
        """Test name normalization."""
        assert get_framework("PCI-DSS") == ComplianceFramework.PCI_DSS
        assert get_framework("NIST CSF") == ComplianceFramework.NIST_CSF

    def test_invalid_framework(self):
        """Test invalid framework."""
        assert get_framework("unknown") is None


class TestGetAllFrameworks:
    """Tests for get_all_frameworks function."""

    def test_returns_list(self):
        """Test returns list of frameworks."""
        frameworks = get_all_frameworks()
        assert isinstance(frameworks, list)
        assert len(frameworks) >= 6
        assert ComplianceFramework.PCI_DSS in frameworks


class TestGetControl:
    """Tests for get_control function."""

    def test_valid_control(self):
        """Test getting valid control."""
        control = get_control("PCI.8.3")
        assert control is not None
        assert control.id == "8.3"

    def test_invalid_control(self):
        """Test getting invalid control."""
        control = get_control("INVALID.99.99")
        assert control is None


class TestGetRelatedControls:
    """Tests for get_related_controls function."""

    def test_with_related(self):
        """Test control with related controls."""
        related = get_related_controls("PCI.8.3")
        # PCI.8.3 should have related controls defined
        assert isinstance(related, list)

    def test_invalid_control(self):
        """Test with invalid control."""
        related = get_related_controls("INVALID.1")
        assert related == []


class TestGetControlsByCategory:
    """Tests for get_controls_by_category function."""

    def test_valid_category(self):
        """Test getting controls by category."""
        controls = get_controls_by_category(
            ComplianceFramework.PCI_DSS, "Authentication"
        )
        assert len(controls) >= 1

    def test_invalid_category(self):
        """Test with invalid category."""
        controls = get_controls_by_category(
            ComplianceFramework.PCI_DSS, "Invalid Category"
        )
        assert controls == []


class TestGetControlsByPriority:
    """Tests for get_controls_by_priority function."""

    def test_critical_priority(self):
        """Test getting critical controls."""
        controls = get_controls_by_priority(
            ComplianceFramework.PCI_DSS, ControlPriority.CRITICAL
        )
        assert len(controls) >= 1
        assert all(c.priority == ControlPriority.CRITICAL for c in controls)

    def test_high_priority(self):
        """Test getting high priority controls."""
        controls = get_controls_by_priority(
            ComplianceFramework.PCI_DSS, ControlPriority.HIGH
        )
        assert len(controls) >= 1


class TestMapControlAcrossFrameworks:
    """Tests for map_control_across_frameworks function."""

    def test_cross_framework_mapping(self):
        """Test mapping control across frameworks."""
        mapping = map_control_across_frameworks("PCI.8.3")

        # Should map to other frameworks
        assert isinstance(mapping, dict)

    def test_invalid_control(self):
        """Test with invalid control."""
        mapping = map_control_across_frameworks("INVALID.1")
        assert mapping == {}


class TestGetFrameworkCategories:
    """Tests for get_framework_categories function."""

    def test_pci_categories(self):
        """Test getting PCI-DSS categories."""
        categories = get_framework_categories(ComplianceFramework.PCI_DSS)
        assert len(categories) >= 5
        assert "Network Security" in categories or "Authentication" in categories

    def test_nist_categories(self):
        """Test getting NIST CSF categories."""
        categories = get_framework_categories(ComplianceFramework.NIST_CSF)
        assert "Identify" in categories
        assert "Protect" in categories


class TestCalculateCategoryScore:
    """Tests for calculate_category_score function."""

    def test_all_compliant(self):
        """Test score with all compliant."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="",
            category="Test Category",
        )
        assessments = [
            ControlAssessment(control=control, status=ControlStatus.COMPLIANT),
        ]
        score = calculate_category_score(assessments, "Test Category")
        assert score == 100.0

    def test_all_non_compliant(self):
        """Test score with all non-compliant."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="",
            category="Test Category",
        )
        assessments = [
            ControlAssessment(control=control, status=ControlStatus.NON_COMPLIANT),
        ]
        score = calculate_category_score(assessments, "Test Category")
        assert score == 0.0

    def test_mixed_status(self):
        """Test score with mixed status."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test",
            description="",
            category="Test Category",
        )
        assessments = [
            ControlAssessment(control=control, status=ControlStatus.COMPLIANT),
            ControlAssessment(control=control, status=ControlStatus.PARTIAL),
        ]
        score = calculate_category_score(assessments, "Test Category")
        assert score == 75.0  # (100 + 50) / 2


class TestExportGapAnalysis:
    """Tests for export_gap_analysis function."""

    def test_export_with_gaps(self):
        """Test exporting gap analysis."""
        control = ComplianceControl(
            id="TEST.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Test Control",
            description="",
            category="Test",
            priority=ControlPriority.HIGH,
        )
        assessment = ControlAssessment(
            control=control,
            status=ControlStatus.NON_COMPLIANT,
            gaps=["Gap 1"],
            remediation=["Fix 1"],
        )
        report = ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            target="example.com",
            assessments=[assessment],
        )

        export = export_gap_analysis(report)

        assert export["framework"] == "pci_dss"
        assert export["total_gaps"] == 1
        assert len(export["gaps"]) == 1
        assert export["gaps"][0]["priority"] == "high"

    def test_export_sorted_by_priority(self):
        """Test gaps are sorted by priority."""
        critical = ComplianceControl(
            id="CRIT.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Critical",
            description="",
            category="",
            priority=ControlPriority.CRITICAL,
        )
        low = ComplianceControl(
            id="LOW.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Low",
            description="",
            category="",
            priority=ControlPriority.LOW,
        )

        report = ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            target="example.com",
            assessments=[
                ControlAssessment(control=low, status=ControlStatus.NON_COMPLIANT),
                ControlAssessment(control=critical, status=ControlStatus.NON_COMPLIANT),
            ],
        )

        export = export_gap_analysis(report)

        # Critical should come first
        assert export["gaps"][0]["priority"] == "critical"


class TestIntegration:
    """Integration tests for compliance mapping."""

    def test_full_assessment_workflow(self):
        """Test full assessment workflow."""
        ctx = Context(target="example.com")
        ctx.add(
            "findings",
            [
                {
                    "title": "Weak Password Policy",
                    "severity": "high",
                    "category": "authentication",
                },
                {
                    "title": "Missing Encryption",
                    "severity": "critical",
                    "category": "encryption",
                },
                {
                    "title": "No Vulnerability Scanning",
                    "severity": "high",
                    "category": "vulnerability",
                },
            ],
        )
        ctx.add(
            "exposure_scan",
            {
                "findings": [
                    {
                        "title": "API Key Exposed",
                        "severity": "critical",
                        "category": "credentials",
                    },
                ]
            },
        )

        result = assess_compliance(
            ctx,
            {
                "frameworks": ["pci_dss", "hipaa"],
                "generate_recommendations": True,
            },
        )

        assessment = result.get("compliance_assessment")

        # Should have reports for both frameworks
        assert len(assessment["reports"]) == 2

        # Should have overall posture
        assert "overall_posture" in assessment
        assert assessment["overall_posture"]["frameworks_assessed"] == 2

        # Should have priority remediations
        assert len(assessment["priority_remediations"]) >= 1

    def test_clean_target_assessment(self):
        """Test assessment of target with no findings."""
        ctx = Context(target="clean.example.com")

        result = assess_compliance(ctx, {"frameworks": ["pci_dss"]})
        assessment = result.get("compliance_assessment")

        # Should mostly be not_assessed (no findings to evaluate)
        report = assessment["reports"][0]
        assert report["not_assessed_count"] >= report["non_compliant_count"]
