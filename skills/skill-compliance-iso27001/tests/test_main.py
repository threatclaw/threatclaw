"""Tests for skill-compliance-iso27001."""

import pytest
from src.main import (
    ANNEX_A_CONTROLS,
    CONTROL_MAP,
    ControlCategory,
    ControlStatus,
    MaturityLevel,
    ControlAssessment,
    SoAEntry,
    SkillInput,
    SkillOutput,
    map_finding_to_controls,
    assess_control,
    generate_soa,
    calculate_compliance_score,
    calculate_category_scores,
    _overall_maturity,
    _build_action_plan,
    run,
)


# ── 1. Control count ─────────────────────────────────────

class TestControlDefinitions:
    def test_total_control_count_is_93(self):
        """All 93 Annex A controls must be defined."""
        assert len(ANNEX_A_CONTROLS) == 93

    def test_control_map_has_93_entries(self):
        """Control map should have one entry per control."""
        assert len(CONTROL_MAP) == 93

    def test_all_control_ids_unique(self):
        """All control IDs must be unique."""
        ids = [c.id for c in ANNEX_A_CONTROLS]
        assert len(ids) == len(set(ids))


# ── 2. Category assignment ────────────────────────────────

class TestCategoryAssignment:
    def test_organizational_count(self):
        """A.5 organizational controls: 37 controls."""
        count = sum(
            1 for c in ANNEX_A_CONTROLS
            if c.category == ControlCategory.ORGANIZATIONAL
        )
        assert count == 37

    def test_people_count(self):
        """A.6 people controls: 8 controls."""
        count = sum(
            1 for c in ANNEX_A_CONTROLS
            if c.category == ControlCategory.PEOPLE
        )
        assert count == 8

    def test_physical_count(self):
        """A.7 physical controls: 14 controls."""
        count = sum(
            1 for c in ANNEX_A_CONTROLS
            if c.category == ControlCategory.PHYSICAL
        )
        assert count == 14

    def test_technological_count(self):
        """A.8 technological controls: 34 controls."""
        count = sum(
            1 for c in ANNEX_A_CONTROLS
            if c.category == ControlCategory.TECHNOLOGICAL
        )
        assert count == 34

    def test_a5_controls_are_organizational(self):
        """All A.5.x controls should be ORGANIZATIONAL."""
        for c in ANNEX_A_CONTROLS:
            if c.id.startswith("A.5."):
                assert c.category == ControlCategory.ORGANIZATIONAL, f"{c.id} should be ORGANIZATIONAL"

    def test_a8_controls_are_technological(self):
        """All A.8.x controls should be TECHNOLOGICAL."""
        for c in ANNEX_A_CONTROLS:
            if c.id.startswith("A.8."):
                assert c.category == ControlCategory.TECHNOLOGICAL, f"{c.id} should be TECHNOLOGICAL"


# ── 3. Finding-to-control mapping ─────────────────────────

class TestFindingMapping:
    def test_vuln_scan_maps_to_a88(self):
        """Vulnerability scan findings should map to A.8.8."""
        finding = {
            "source": "vuln-scan",
            "title": "CVE-2024-1234 SQL Injection",
            "severity": "high",
        }
        controls = map_finding_to_controls(finding)
        assert "A.8.8" in controls

    def test_secrets_finding_maps_to_a517_a533(self):
        """Secrets findings should map to A.5.17 and A.5.33."""
        finding = {
            "source": "secrets",
            "title": "API key exposed in repository",
            "severity": "critical",
        }
        controls = map_finding_to_controls(finding)
        assert "A.5.17" in controls
        assert "A.5.33" in controls

    def test_cloud_posture_maps_to_a523(self):
        """Cloud posture findings should map to A.5.23."""
        finding = {
            "source": "cloud-posture",
            "title": "S3 bucket public access",
            "severity": "high",
        }
        controls = map_finding_to_controls(finding)
        assert "A.5.23" in controls

    def test_keyword_based_mapping(self):
        """Keyword-based mapping should work regardless of source."""
        finding = {
            "source": "custom-scanner",
            "title": "Weak encryption detected on TLS endpoint",
            "description": "TLS 1.0 still enabled, cryptography weaknesses found",
        }
        controls = map_finding_to_controls(finding)
        assert "A.8.24" in controls

    def test_empty_finding_returns_empty(self):
        """An empty finding should return no controls."""
        controls = map_finding_to_controls({})
        assert controls == []

    def test_phishing_maps_to_a63(self):
        """Phishing findings should map to A.6.3 (awareness training)."""
        finding = {
            "source": "phishing",
            "title": "Phishing campaign results",
        }
        controls = map_finding_to_controls(finding)
        assert "A.6.3" in controls


# ── 4. Control assessment ─────────────────────────────────

class TestControlAssessment:
    def test_conforming_when_no_findings(self):
        """Control with no related findings should be CONFORMING."""
        control = CONTROL_MAP["A.5.1"]
        assessment = assess_control(control, [])
        assert assessment.status == ControlStatus.CONFORMING

    def test_non_conforming_with_critical_findings(self):
        """Control with critical findings should be NON_CONFORMING."""
        control = CONTROL_MAP["A.8.8"]
        findings = [
            {
                "source": "vuln-scan",
                "title": "Critical RCE vulnerability",
                "severity": "critical",
                "description": "Remote code execution via vulnerability in web server",
            }
        ]
        assessment = assess_control(control, findings)
        assert assessment.status == ControlStatus.NON_CONFORMING
        assert len(assessment.gaps) > 0
        assert len(assessment.recommendations) > 0

    def test_partial_with_medium_findings(self):
        """Control with only medium findings should be PARTIAL."""
        control = CONTROL_MAP["A.8.8"]
        findings = [
            {
                "source": "vuln-scan",
                "title": "Medium vulnerability found",
                "severity": "medium",
                "description": "Information disclosure vulnerability detected",
            }
        ]
        assessment = assess_control(control, findings)
        assert assessment.status == ControlStatus.PARTIAL


# ── 5. Maturity level ─────────────────────────────────────

class TestMaturityLevel:
    def test_initial_maturity_low_score(self):
        """Score < 25 should give INITIAL maturity."""
        assert _overall_maturity(10.0) == MaturityLevel.INITIAL

    def test_managed_maturity(self):
        """Score 25-49 should give MANAGED maturity."""
        assert _overall_maturity(30.0) == MaturityLevel.MANAGED

    def test_defined_maturity(self):
        """Score 50-69 should give DEFINED maturity."""
        assert _overall_maturity(55.0) == MaturityLevel.DEFINED

    def test_measured_maturity(self):
        """Score 70-89 should give MEASURED maturity."""
        assert _overall_maturity(75.0) == MaturityLevel.MEASURED

    def test_optimized_maturity(self):
        """Score >= 90 should give OPTIMIZED maturity."""
        assert _overall_maturity(95.0) == MaturityLevel.OPTIMIZED


# ── 6. SoA generation ────────────────────────────────────

class TestSoAGeneration:
    def test_soa_entry_count_matches_assessments(self):
        """SoA should have one entry per assessment."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="Test 1", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.5.2", title="Test 2", status=ControlStatus.NON_CONFORMING),
            ControlAssessment(control_id="A.5.3", title="Test 3", status=ControlStatus.NOT_APPLICABLE),
        ]
        soa = generate_soa(assessments)
        assert len(soa) == 3

    def test_soa_not_applicable_marked(self):
        """NOT_APPLICABLE controls should be marked as not applicable in SoA."""
        assessments = [
            ControlAssessment(control_id="A.7.1", title="Physical", status=ControlStatus.NOT_APPLICABLE),
        ]
        soa = generate_soa(assessments)
        assert soa[0].applicable is False
        assert "non applicable" in soa[0].justification.lower()

    def test_soa_conforming_justification(self):
        """CONFORMING controls should have conformity justification."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="Policy", status=ControlStatus.CONFORMING),
        ]
        soa = generate_soa(assessments)
        assert soa[0].applicable is True
        assert "conforme" in soa[0].justification.lower()


# ── 7. Compliance score calculation ───────────────────────

class TestComplianceScore:
    def test_100_percent_when_all_conforming(self):
        """All conforming -> 100%."""
        assessments = [
            ControlAssessment(control_id=f"A.5.{i}", title=f"T{i}", status=ControlStatus.CONFORMING)
            for i in range(1, 6)
        ]
        score = calculate_compliance_score(assessments)
        assert score == 100.0

    def test_0_percent_when_all_non_conforming(self):
        """All non-conforming -> 0%."""
        assessments = [
            ControlAssessment(control_id=f"A.5.{i}", title=f"T{i}", status=ControlStatus.NON_CONFORMING)
            for i in range(1, 6)
        ]
        score = calculate_compliance_score(assessments)
        assert score == 0.0

    def test_mixed_score(self):
        """2 conforming + 2 partial + 1 non-conforming out of 5 applicable -> (2 + 0.5*2) / 5 * 100 = 60%."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="T1", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.5.2", title="T2", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.5.3", title="T3", status=ControlStatus.PARTIAL),
            ControlAssessment(control_id="A.5.4", title="T4", status=ControlStatus.PARTIAL),
            ControlAssessment(control_id="A.5.5", title="T5", status=ControlStatus.NON_CONFORMING),
        ]
        score = calculate_compliance_score(assessments)
        assert score == 60.0

    def test_score_excludes_not_applicable(self):
        """NOT_APPLICABLE controls should not count in score denominator."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="T1", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.5.2", title="T2", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.5.3", title="T3", status=ControlStatus.NOT_APPLICABLE),
        ]
        # 2 conforming out of 2 applicable = 100%
        score = calculate_compliance_score(assessments)
        assert score == 100.0

    def test_score_zero_when_all_not_applicable(self):
        """All NOT_APPLICABLE should return 0 (no applicable controls)."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="T1", status=ControlStatus.NOT_APPLICABLE),
        ]
        score = calculate_compliance_score(assessments)
        assert score == 0.0

    def test_score_empty_assessments(self):
        """Empty assessments should return 0."""
        score = calculate_compliance_score([])
        assert score == 0.0


# ── 8. Category scores ───────────────────────────────────

class TestCategoryScores:
    def test_category_scores_returns_four_categories(self):
        """Should return a score for each of the 4 categories."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="T1", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.6.1", title="T2", status=ControlStatus.CONFORMING),
            ControlAssessment(control_id="A.7.1", title="T3", status=ControlStatus.NON_CONFORMING),
            ControlAssessment(control_id="A.8.1", title="T4", status=ControlStatus.PARTIAL),
        ]
        cat_scores = calculate_category_scores(assessments)
        assert len(cat_scores) == 4

        categories = {cs.category for cs in cat_scores}
        assert categories == {
            ControlCategory.ORGANIZATIONAL,
            ControlCategory.PEOPLE,
            ControlCategory.PHYSICAL,
            ControlCategory.TECHNOLOGICAL,
        }

    def test_organizational_score_correct(self):
        """Organizational category with 1 conforming out of 1 should be 100%."""
        assessments = [
            ControlAssessment(control_id="A.5.1", title="T1", status=ControlStatus.CONFORMING),
        ]
        cat_scores = calculate_category_scores(assessments)
        org_score = next(
            cs for cs in cat_scores if cs.category == ControlCategory.ORGANIZATIONAL
        )
        assert org_score.score == 100.0
        assert org_score.controls_met == 1
        assert org_score.control_count == 1


# ── 9. Full pipeline with mocked findings ────────────────

class TestFullPipeline:
    @pytest.mark.asyncio
    async def test_run_full_scope_no_findings(self):
        """Full scope with no findings should return 100% (all conforming)."""
        output = await run(SkillInput(scope="full", include_soa=True))
        assert output.success is True
        assert output.result is not None
        assert output.result.overall_score == 100.0
        assert output.result.total_controls == 93
        assert output.result.conforming_count == 93
        assert output.result.maturity_level == MaturityLevel.OPTIMIZED
        assert output.result.soa is not None
        assert len(output.result.soa) == 93

    @pytest.mark.asyncio
    async def test_run_category_filter(self):
        """Category scope should filter controls by prefix."""
        output = await run(SkillInput(scope="category", category_filter="A.6"))
        assert output.success is True
        assert output.result is not None
        assert output.result.total_controls == 8

    @pytest.mark.asyncio
    async def test_run_invalid_category_filter(self):
        """Invalid category filter should return an error."""
        output = await run(SkillInput(scope="category", category_filter="A.99"))
        assert output.success is False
        assert output.error is not None
        assert "A.99" in output.error

    @pytest.mark.asyncio
    async def test_run_without_soa(self):
        """Setting include_soa=False should omit the SoA from results."""
        output = await run(SkillInput(include_soa=False))
        assert output.success is True
        assert output.result.soa is None

    @pytest.mark.asyncio
    async def test_summary_fr_contains_score(self):
        """Summary in French should contain the compliance score."""
        output = await run(SkillInput())
        assert output.success is True
        assert "100.0%" in output.result.summary_fr


# ── 10. Edge cases ────────────────────────────────────────

class TestEdgeCases:
    def test_control_has_title_fr(self):
        """Every control should have a non-empty title_fr."""
        for c in ANNEX_A_CONTROLS:
            assert c.title_fr, f"{c.id} has empty title_fr"

    def test_action_plan_prioritises_non_conforming(self):
        """Action plan should list non-conforming items before partial."""
        assessments = [
            ControlAssessment(
                control_id="A.5.1",
                title="T1",
                status=ControlStatus.PARTIAL,
                recommendations=["Improve partial"],
            ),
            ControlAssessment(
                control_id="A.5.2",
                title="T2",
                status=ControlStatus.NON_CONFORMING,
                recommendations=["Fix critical"],
            ),
        ]
        plan = _build_action_plan(assessments)
        assert len(plan) == 2
        assert plan[0].startswith("[PRIORITAIRE]")
        assert plan[1].startswith("[AMELIORATION]")

    def test_maturity_enum_values(self):
        """Maturity levels should have values 1-5."""
        assert MaturityLevel.INITIAL.value == 1
        assert MaturityLevel.MANAGED.value == 2
        assert MaturityLevel.DEFINED.value == 3
        assert MaturityLevel.MEASURED.value == 4
        assert MaturityLevel.OPTIMIZED.value == 5

    def test_control_status_enum_values(self):
        """ControlStatus enum should have the expected members."""
        assert ControlStatus.CONFORMING.value == "conforming"
        assert ControlStatus.PARTIAL.value == "partial"
        assert ControlStatus.NON_CONFORMING.value == "non_conforming"
        assert ControlStatus.NOT_APPLICABLE.value == "not_applicable"

    def test_mapping_returns_sorted_control_ids(self):
        """map_finding_to_controls should return sorted control IDs."""
        finding = {
            "source": "secrets",
            "title": "Exposed API key in git repository",
            "severity": "critical",
        }
        controls = map_finding_to_controls(finding)
        assert controls == sorted(controls)
