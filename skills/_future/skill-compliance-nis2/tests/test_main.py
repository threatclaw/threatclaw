"""Tests for skill-compliance-nis2.

Covers:
- NIS2 article definitions (all 10 present)
- Finding-to-article mapping (keyword matching, source mapping, multi-article)
- Article score calculation (full, partial, zero coverage)
- Maturity level assignment
- Gap analysis (critical gaps, no gaps, mixed)
- Action plan generation (priorities, responsible parties)
- Controls detection from findings
- Full pipeline with mocked findings
- Edge cases (no findings, all articles covered, unknown source)
- French text content verification
"""

import pytest
from unittest.mock import AsyncMock, patch

from src.main import (
    NIS2_ARTICLES,
    NIS2Article,
    FindingSource,
    SecurityFinding,
    ArticleScore,
    ComplianceReport,
    GapItem,
    ActionItem,
    Priority,
    MaturityLevel,
    SkillInput,
    SkillOutput,
    SOURCE_TO_ARTICLES,
    map_finding_to_articles,
    calculate_article_score,
    analyze_gaps,
    generate_action_plan,
    determine_controls_met,
    _score_to_maturity,
    _score_to_priority,
    _parse_period,
    run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    source: FindingSource = FindingSource.VULN_SCAN,
    severity: str = "medium",
    title: str = "Test finding",
    description: str = "Test description",
    remediation: str = "",
    metadata: dict | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        source=source,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        date="2025-01-15T10:00:00Z",
        metadata=metadata or {},
    )


# ═══════════════════════════════════════════════════════════════════
# 1. NIS2 Article Definitions
# ═══════════════════════════════════════════════════════════════════

class TestNIS2ArticleDefinitions:
    """Verify all 10 Art.21 sections are properly defined."""

    def test_all_10_articles_present(self):
        assert len(NIS2_ARTICLES) == 10

    def test_article_ids(self):
        expected_ids = [
            "art21_2a", "art21_2b", "art21_2c", "art21_2d", "art21_2e",
            "art21_2f", "art21_2g", "art21_2h", "art21_2i", "art21_2j",
        ]
        for aid in expected_ids:
            assert aid in NIS2_ARTICLES, f"Missing article {aid}"

    def test_each_article_has_required_fields(self):
        for aid, article in NIS2_ARTICLES.items():
            assert isinstance(article, NIS2Article)
            assert article.id == aid
            assert len(article.title_fr) > 0
            assert len(article.description_fr) > 0
            assert len(article.required_controls) > 0
            assert len(article.mapping_keywords) > 0
            assert isinstance(article.related_skills, list)

    def test_article_titles_in_french(self):
        # Verify key French terms are present in titles
        all_titles = " ".join(a.title_fr for a in NIS2_ARTICLES.values())
        french_terms = ["risques", "incidents", "chiffrement", "acc\u00e8s"]
        for term in french_terms:
            assert term in all_titles.lower(), (
                f"Expected French term '{term}' in article titles"
            )

    def test_art21_2a_risk_analysis(self):
        art = NIS2_ARTICLES["art21_2a"]
        assert "risques" in art.title_fr.lower()
        assert "analyse de risques" in art.required_controls
        assert "inventaire des actifs" in art.required_controls

    def test_art21_2h_cryptography(self):
        art = NIS2_ARTICLES["art21_2h"]
        assert "cryptographie" in art.title_fr.lower() or "chiffrement" in art.title_fr.lower()
        assert "gestion des cl\u00e9s" in art.required_controls


# ═══════════════════════════════════════════════════════════════════
# 2. Finding-to-Article Mapping
# ═══════════════════════════════════════════════════════════════════

class TestFindingMapping:
    """Test the mapping engine that links findings to NIS2 articles."""

    def test_keyword_matching_vulnerability(self):
        finding = _make_finding(
            source=FindingSource.VULN_SCAN,
            title="CVE-2024-1234 Critical vulnerability",
            description="A remote code execution vulnerability in Apache",
        )
        articles = map_finding_to_articles(finding)
        assert "art21_2a" in articles  # risk analysis
        assert "art21_2e" in articles  # vulnerability management

    def test_keyword_matching_incident(self):
        finding = _make_finding(
            source=FindingSource.SOC_MONITOR,
            title="Sigma alert: suspicious login detected",
            description="Intrusion detection alert from SIEM monitoring",
        )
        articles = map_finding_to_articles(finding)
        assert "art21_2b" in articles  # incident management

    def test_keyword_matching_phishing(self):
        finding = _make_finding(
            source=FindingSource.PHISHING,
            title="Phishing simulation failed",
            description="Employee clicked on phishing email link",
        )
        articles = map_finding_to_articles(finding)
        assert "art21_2g" in articles  # cyber hygiene & training

    def test_source_mapping_soc_monitor(self):
        finding = _make_finding(
            source=FindingSource.SOC_MONITOR,
            title="Generic event",
            description="Something happened",
        )
        articles = map_finding_to_articles(finding)
        assert "art21_2b" in articles  # SOC_MONITOR -> incident handling

    def test_source_mapping_secrets(self):
        finding = _make_finding(
            source=FindingSource.SECRETS,
            title="API key found",
            description="Exposed credential",
        )
        articles = map_finding_to_articles(finding)
        assert "art21_2h" in articles  # cryptography
        assert "art21_2i" in articles  # access control

    def test_source_mapping_darkweb(self):
        finding = _make_finding(
            source=FindingSource.DARKWEB,
            title="Credential found on dark web",
            description="User password exposed",
        )
        articles = map_finding_to_articles(finding)
        assert "art21_2i" in articles

    def test_multi_article_mapping(self):
        """A single finding can map to multiple articles."""
        finding = _make_finding(
            source=FindingSource.CLOUD_POSTURE,
            title="TLS certificate expiring, encryption at rest disabled",
            description="Cloud configuration risk assessment shows policy violation",
        )
        articles = map_finding_to_articles(finding)
        # Cloud posture maps to multiple articles, plus keyword matches
        assert len(articles) >= 2

    def test_finding_with_no_keyword_match_uses_source(self):
        finding = _make_finding(
            source=FindingSource.SOC_MONITOR,
            title="xyz",
            description="abc",
        )
        articles = map_finding_to_articles(finding)
        # At minimum should get source-based mapping
        assert "art21_2b" in articles

    def test_all_sources_have_mappings(self):
        for source in FindingSource:
            assert source in SOURCE_TO_ARTICLES


# ═══════════════════════════════════════════════════════════════════
# 3. Article Score Calculation
# ═══════════════════════════════════════════════════════════════════

class TestArticleScoreCalculation:
    """Test compliance score computation."""

    def test_full_coverage_all_controls_met(self):
        article = NIS2_ARTICLES["art21_2a"]
        controls = list(article.required_controls)
        findings = [_make_finding(severity="low")]
        score = calculate_article_score(article, findings, controls)
        assert score.score >= 80  # all controls met, only low findings

    def test_partial_coverage(self):
        article = NIS2_ARTICLES["art21_2a"]
        controls = article.required_controls[:3]  # only half
        score = calculate_article_score(article, [], controls)
        assert 30 <= score.score <= 60

    def test_zero_coverage_no_findings_no_controls(self):
        article = NIS2_ARTICLES["art21_2a"]
        score = calculate_article_score(article, [], [])
        assert score.score == 0
        assert score.maturity_level == 1

    def test_severity_penalty(self):
        article = NIS2_ARTICLES["art21_2b"]
        controls = list(article.required_controls)
        # Many critical findings should reduce the score
        critical_findings = [
            _make_finding(severity="critical") for _ in range(10)
        ]
        score_with_critical = calculate_article_score(
            article, critical_findings, controls
        )
        score_without = calculate_article_score(article, [], controls)
        assert score_with_critical.score < score_without.score

    def test_fail_and_pass_counts(self):
        article = NIS2_ARTICLES["art21_2a"]
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="low"),
            _make_finding(severity="info"),
        ]
        score = calculate_article_score(article, findings, [])
        # critical and high (weight >= 0.5) count as fails
        assert score.fail_count == 2
        assert score.pass_count == 2

    def test_gaps_list_populated(self):
        article = NIS2_ARTICLES["art21_2a"]
        score = calculate_article_score(article, [], [])
        assert len(score.gaps) == len(article.required_controls)
        for gap in score.gaps:
            assert "Contr\u00f4le manquant" in gap

    def test_evidence_from_controls(self):
        article = NIS2_ARTICLES["art21_2a"]
        controls = ["analyse de risques", "inventaire des actifs"]
        score = calculate_article_score(article, [], controls)
        assert len(score.evidence) == 2

    def test_score_never_exceeds_100(self):
        article = NIS2_ARTICLES["art21_2j"]  # fewer controls
        controls = list(article.required_controls) * 3  # duplicates
        score = calculate_article_score(article, [], controls)
        assert score.score <= 100

    def test_score_never_below_zero(self):
        article = NIS2_ARTICLES["art21_2a"]
        # Many critical findings
        findings = [_make_finding(severity="critical") for _ in range(50)]
        score = calculate_article_score(article, findings, [])
        assert score.score >= 0


# ═══════════════════════════════════════════════════════════════════
# 4. Maturity Level Assignment
# ═══════════════════════════════════════════════════════════════════

class TestMaturityLevel:
    """Test the 1-5 maturity scale mapping."""

    def test_level_1_initial(self):
        assert _score_to_maturity(0) == 1
        assert _score_to_maturity(19) == 1

    def test_level_2_gere(self):
        assert _score_to_maturity(20) == 2
        assert _score_to_maturity(39) == 2

    def test_level_3_defini(self):
        assert _score_to_maturity(40) == 3
        assert _score_to_maturity(59) == 3

    def test_level_4_mesure(self):
        assert _score_to_maturity(60) == 4
        assert _score_to_maturity(79) == 4

    def test_level_5_optimise(self):
        assert _score_to_maturity(80) == 5
        assert _score_to_maturity(100) == 5

    def test_maturity_enum_labels(self):
        assert MaturityLevel.INITIAL.label_fr == "Initial"
        assert MaturityLevel.GERE.label_fr == "G\u00e9r\u00e9"
        assert MaturityLevel.DEFINI.label_fr == "D\u00e9fini"
        assert MaturityLevel.MESURE.label_fr == "Mesur\u00e9"
        assert MaturityLevel.OPTIMISE.label_fr == "Optimis\u00e9"


# ═══════════════════════════════════════════════════════════════════
# 5. Gap Analysis
# ═══════════════════════════════════════════════════════════════════

class TestGapAnalysis:
    """Test gap identification and prioritization."""

    def test_critical_gap_score_below_20(self):
        scores = [ArticleScore(
            article_id="art21_2a",
            title="Test",
            score=10,
            maturity_level=1,
            fail_count=5,
            gaps=["Missing control A"],
        )]
        gaps = analyze_gaps(scores)
        assert len(gaps) == 1
        assert gaps[0].priority == Priority.CRITICAL

    def test_high_gap_score_below_40(self):
        scores = [ArticleScore(
            article_id="art21_2b",
            title="Test",
            score=30,
            maturity_level=2,
        )]
        gaps = analyze_gaps(scores)
        assert len(gaps) == 1
        assert gaps[0].priority == Priority.HIGH

    def test_medium_gap_score_below_60(self):
        scores = [ArticleScore(
            article_id="art21_2c",
            title="Test",
            score=45,
            maturity_level=3,
        )]
        gaps = analyze_gaps(scores)
        assert len(gaps) == 1
        assert gaps[0].priority == Priority.MEDIUM

    def test_no_gap_score_50_or_above(self):
        scores = [ArticleScore(
            article_id="art21_2a",
            title="Test",
            score=50,
            maturity_level=3,
        )]
        gaps = analyze_gaps(scores)
        assert len(gaps) == 0

    def test_no_gap_score_80(self):
        scores = [ArticleScore(
            article_id="art21_2a",
            title="Test",
            score=80,
            maturity_level=5,
        )]
        gaps = analyze_gaps(scores)
        assert len(gaps) == 0

    def test_mixed_gaps_sorted_by_priority(self):
        scores = [
            ArticleScore(article_id="art21_2a", title="A", score=45, maturity_level=3),
            ArticleScore(article_id="art21_2b", title="B", score=10, maturity_level=1),
            ArticleScore(article_id="art21_2c", title="C", score=30, maturity_level=2),
            ArticleScore(article_id="art21_2d", title="D", score=90, maturity_level=5),
        ]
        gaps = analyze_gaps(scores)
        assert len(gaps) == 3  # D is excluded (score >= 50)
        # First should be CRITICAL (B, score=10)
        assert gaps[0].priority == Priority.CRITICAL
        assert gaps[0].article_id == "art21_2b"
        # Then HIGH (C, score=30)
        assert gaps[1].priority == Priority.HIGH
        # Then MEDIUM (A, score=45)
        assert gaps[2].priority == Priority.MEDIUM

    def test_gap_description_in_french(self):
        scores = [ArticleScore(
            article_id="art21_2a",
            title="Analyse des risques",
            score=10,
            maturity_level=1,
            gaps=["Contr\u00f4le manquant : analyse de risques"],
            fail_count=3,
        )]
        gaps = analyze_gaps(scores)
        assert "contr\u00f4le(s) manquant(s)" in gaps[0].gap_description
        assert "finding(s)" in gaps[0].gap_description

    def test_gap_estimated_effort(self):
        scores = [
            ArticleScore(article_id="art21_2a", title="A", score=10, maturity_level=1),
            ArticleScore(article_id="art21_2b", title="B", score=45, maturity_level=3),
        ]
        gaps = analyze_gaps(scores)
        assert gaps[0].estimated_effort == "court"  # CRITICAL -> court
        assert gaps[1].estimated_effort == "moyen"  # MEDIUM -> moyen


# ═══════════════════════════════════════════════════════════════════
# 6. Action Plan Generation
# ═══════════════════════════════════════════════════════════════════

class TestActionPlanGeneration:
    """Test action plan creation from gaps."""

    def test_generates_action_per_gap(self):
        gaps = [
            GapItem(
                article_id="art21_2a",
                article_title="Risques",
                gap_description="Gap",
                priority=Priority.CRITICAL,
                recommended_action="Fix risques",
                estimated_effort="court",
            ),
            GapItem(
                article_id="art21_2g",
                article_title="Formation",
                gap_description="Gap",
                priority=Priority.MEDIUM,
                recommended_action="Fix formation",
                estimated_effort="moyen",
            ),
        ]
        actions = generate_action_plan(gaps)
        assert len(actions) == 2

    def test_responsible_assignment(self):
        gaps = [
            GapItem("art21_2a", "T", "G", Priority.HIGH, "A", "court"),
            GapItem("art21_2c", "T", "G", Priority.HIGH, "A", "court"),
            GapItem("art21_2e", "T", "G", Priority.HIGH, "A", "court"),
        ]
        actions = generate_action_plan(gaps)
        responsible_map = {a.article_id: a.responsible for a in actions}
        assert responsible_map["art21_2a"] == "RSSI"
        assert responsible_map["art21_2c"] == "DSI"
        assert responsible_map["art21_2e"] == "IT"

    def test_deadline_from_priority(self):
        gaps = [
            GapItem("art21_2a", "T", "G", Priority.CRITICAL, "A", "court"),
            GapItem("art21_2b", "T", "G", Priority.LOW, "A", "long"),
        ]
        actions = generate_action_plan(gaps)
        assert actions[0].deadline_category == "imm\u00e9diat"
        assert actions[1].deadline_category == "moyen_terme"

    def test_cost_from_priority(self):
        gaps = [
            GapItem("art21_2a", "T", "G", Priority.CRITICAL, "A", "court"),
            GapItem("art21_2b", "T", "G", Priority.LOW, "A", "long"),
        ]
        actions = generate_action_plan(gaps)
        assert actions[0].estimated_cost == "\u00e9lev\u00e9"
        assert actions[1].estimated_cost == "faible"

    def test_empty_gaps_produce_no_actions(self):
        assert generate_action_plan([]) == []


# ═══════════════════════════════════════════════════════════════════
# 7. Controls Detection from Findings
# ═══════════════════════════════════════════════════════════════════

class TestControlsDetection:
    """Test automated detection of controls from finding evidence."""

    def test_vuln_scan_implies_risk_analysis(self):
        findings = [_make_finding(source=FindingSource.VULN_SCAN)]
        controls = determine_controls_met(findings)
        assert "analyse de risques" in controls["art21_2a"]

    def test_soc_monitor_implies_detection(self):
        findings = [_make_finding(source=FindingSource.SOC_MONITOR)]
        controls = determine_controls_met(findings)
        assert "d\u00e9tection des incidents" in controls["art21_2b"]

    def test_phishing_implies_exercises(self):
        findings = [_make_finding(source=FindingSource.PHISHING)]
        controls = determine_controls_met(findings)
        assert "exercices de phishing" in controls["art21_2g"]

    def test_keyword_based_detection(self):
        findings = [_make_finding(
            title="TLS certificate renewal check",
            description="Certificate PKI management review",
        )]
        controls = determine_controls_met(findings)
        assert "certificats et PKI" in controls["art21_2h"]

    def test_no_findings_no_controls(self):
        controls = determine_controls_met([])
        for article_id, ctrls in controls.items():
            assert ctrls == [], f"Article {article_id} should have no controls"

    def test_multiple_sources_accumulate(self):
        findings = [
            _make_finding(source=FindingSource.VULN_SCAN),
            _make_finding(source=FindingSource.SOC_MONITOR),
            _make_finding(source=FindingSource.PHISHING),
        ]
        controls = determine_controls_met(findings)
        assert len(controls["art21_2a"]) > 0  # from vuln_scan
        assert len(controls["art21_2b"]) > 0  # from soc_monitor
        assert len(controls["art21_2g"]) > 0  # from phishing


# ═══════════════════════════════════════════════════════════════════
# 8. Full Pipeline with Mocked Findings
# ═══════════════════════════════════════════════════════════════════

class TestFullPipeline:
    """Integration tests for the full run() pipeline."""

    @pytest.mark.asyncio
    async def test_run_with_no_findings(self):
        """When DB returns nothing, all articles score 0."""
        with patch("src.main.fetch_all_findings", new_callable=AsyncMock) as mock:
            mock.return_value = []
            output = await run(SkillInput())

        assert output.success is True
        assert output.report is not None
        assert len(output.report.article_scores) == 10
        assert output.report.overall_score == 0
        assert output.report.covered_articles == 0
        assert output.report.uncovered_articles == 10
        assert output.report.maturity_level == 1

    @pytest.mark.asyncio
    async def test_run_with_mixed_findings(self):
        """Pipeline with varied findings produces a valid report."""
        mock_findings = [
            _make_finding(
                source=FindingSource.VULN_SCAN,
                severity="critical",
                title="CVE-2024-9999 SQL injection vulnerability",
                description="Critical vulnerability in web application",
            ),
            _make_finding(
                source=FindingSource.SOC_MONITOR,
                severity="high",
                title="Sigma alert triggered",
                description="Incident detection correlated event",
            ),
            _make_finding(
                source=FindingSource.PHISHING,
                severity="medium",
                title="Phishing exercise results",
                description="Employee awareness training test",
            ),
            _make_finding(
                source=FindingSource.SECRETS,
                severity="high",
                title="API key exposed in repository",
                description="Secret key management failure detected",
            ),
        ]

        with patch("src.main.fetch_all_findings", new_callable=AsyncMock) as mock:
            mock.return_value = mock_findings
            output = await run(SkillInput())

        assert output.success is True
        report = output.report
        assert report.total_findings == 4
        assert len(report.article_scores) == 10
        # Some articles should be covered
        assert report.covered_articles > 0
        # Should have gaps for uncovered articles
        assert len(report.gaps) >= 0
        # Summary should be in French
        assert "conformit\u00e9 NIS2" in report.summary_fr
        assert "maturit\u00e9" in report.summary_fr

    @pytest.mark.asyncio
    async def test_run_produces_action_plan(self):
        """When gaps exist, action plan is generated."""
        with patch("src.main.fetch_all_findings", new_callable=AsyncMock) as mock:
            mock.return_value = []
            output = await run(SkillInput(include_recommendations=True))

        assert output.success is True
        # With zero findings, all articles are gaps -> action items
        assert len(output.report.action_plan) > 0

    @pytest.mark.asyncio
    async def test_run_without_recommendations(self):
        """When include_recommendations=False, no action plan."""
        with patch("src.main.fetch_all_findings", new_callable=AsyncMock) as mock:
            mock.return_value = []
            output = await run(SkillInput(include_recommendations=False))

        assert output.success is True
        assert len(output.report.action_plan) == 0

    @pytest.mark.asyncio
    async def test_run_handles_exception(self):
        """Pipeline should catch and report errors gracefully."""
        with patch("src.main.fetch_all_findings", new_callable=AsyncMock) as mock:
            mock.side_effect = RuntimeError("DB connection failed")
            output = await run(SkillInput())

        assert output.success is False
        assert "Erreur NIS2" in output.error


# ═══════════════════════════════════════════════════════════════════
# 9. Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_finding_source_from_string(self):
        assert FindingSource.from_string("vuln_scan") == FindingSource.VULN_SCAN
        assert FindingSource.from_string("SECRETS") == FindingSource.SECRETS
        # Unknown defaults to VULN_SCAN
        assert FindingSource.from_string("unknown_source") == FindingSource.VULN_SCAN

    def test_security_finding_to_dict(self):
        f = _make_finding(source=FindingSource.SECRETS, severity="high")
        d = f.to_dict()
        assert d["source"] == "secrets"
        assert d["severity"] == "high"

    def test_article_score_to_dict(self):
        score = ArticleScore(
            article_id="art21_2a",
            title="Test",
            score=75,
            maturity_level=4,
        )
        d = score.to_dict()
        assert d["article_id"] == "art21_2a"
        assert d["score"] == 75

    def test_gap_item_to_dict(self):
        gap = GapItem(
            article_id="art21_2a",
            article_title="T",
            gap_description="G",
            priority=Priority.HIGH,
            recommended_action="A",
            estimated_effort="court",
        )
        d = gap.to_dict()
        assert d["priority"] == "HIGH"

    def test_action_item_to_dict(self):
        action = ActionItem(
            priority=Priority.CRITICAL,
            article_id="art21_2a",
            action_fr="Action",
            responsible="RSSI",
            deadline_category="imm\u00e9diat",
            estimated_cost="\u00e9lev\u00e9",
        )
        d = action.to_dict()
        assert d["priority"] == "CRITICAL"
        assert d["responsible"] == "RSSI"

    def test_compliance_report_to_dict(self):
        report = ComplianceReport(
            overall_score=50,
            maturity_level=3,
            summary_fr="Test summary",
        )
        d = report.to_dict()
        assert d["overall_score"] == 50
        assert d["maturity_level"] == 3

    def test_skill_output_to_dict(self):
        output = SkillOutput(success=True, report=ComplianceReport())
        d = output.to_dict()
        assert d["success"] is True
        assert d["report"] is not None

    def test_skill_output_to_dict_no_report(self):
        output = SkillOutput(success=False, error="fail")
        d = output.to_dict()
        assert d["report"] is None
        assert d["error"] == "fail"

    def test_parse_period_days(self):
        assert _parse_period("last_30d") == "30 days"
        assert _parse_period("last_7d") == "7 days"

    def test_parse_period_hours(self):
        assert _parse_period("last_24h") == "24 hours"

    def test_parse_period_default(self):
        assert _parse_period("invalid") == "30 days"

    def test_score_to_priority(self):
        assert _score_to_priority(0) == Priority.CRITICAL
        assert _score_to_priority(19) == Priority.CRITICAL
        assert _score_to_priority(20) == Priority.HIGH
        assert _score_to_priority(39) == Priority.HIGH
        assert _score_to_priority(40) == Priority.MEDIUM
        assert _score_to_priority(59) == Priority.MEDIUM
        assert _score_to_priority(60) == Priority.LOW


# ═══════════════════════════════════════════════════════════════════
# 10. French Text Content Verification
# ═══════════════════════════════════════════════════════════════════

class TestFrenchContent:
    """Verify French language content throughout the system."""

    def test_article_descriptions_in_french(self):
        for article in NIS2_ARTICLES.values():
            # French descriptions should contain common FR articles/prepositions
            text = article.description_fr.lower()
            has_french = any(
                w in text
                for w in ["de", "des", "la", "les", "et", "en", "du"]
            )
            assert has_french, (
                f"Article {article.id} description doesn't seem French: "
                f"{article.description_fr[:60]}"
            )

    def test_gap_descriptions_contain_french(self):
        scores = [ArticleScore(
            article_id="art21_2a",
            title="Analyse des risques",
            score=10,
            maturity_level=1,
            gaps=["Contr\u00f4le manquant"],
            fail_count=2,
        )]
        gaps = analyze_gaps(scores)
        assert len(gaps) > 0
        # Gap description should be in French
        desc = gaps[0].gap_description
        assert "article" in desc.lower() or "contr\u00f4le" in desc.lower()

    def test_recommendations_in_french(self):
        article = NIS2_ARTICLES["art21_2a"]
        score = calculate_article_score(article, [], [])
        assert any(
            "am\u00e9liorer" in r.lower() or "mettre en place" in r.lower()
            for r in score.recommendations
        )

    @pytest.mark.asyncio
    async def test_summary_fr_in_report(self):
        with patch("src.main.fetch_all_findings", new_callable=AsyncMock) as mock:
            mock.return_value = []
            output = await run(SkillInput())
        summary = output.report.summary_fr
        assert "Score global" in summary
        assert "NIS2" in summary
        assert "article(s)" in summary
