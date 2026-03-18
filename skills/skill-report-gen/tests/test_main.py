"""Tests for skill-report-gen main module.

Covers data models, enums, data aggregation (mocked), score calculation,
executive/technical/compliance report content generation, HTML rendering,
the full run pipeline with mocked DB, edge cases, and ReportData
serialization.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.main import (
    # Enums
    ReportType,
    ReportFramework,
    # Data models
    ReportSection,
    FindingSummary,
    ReportData,
    SkillInput,
    SkillOutput,
    # Data aggregation
    fetch_vuln_scan_summary,
    fetch_soc_alerts_summary,
    fetch_cloud_posture_summary,
    fetch_darkweb_summary,
    fetch_secrets_summary,
    # Score
    calculate_overall_score,
    SCORE_WEIGHTS,
    # Report builders
    build_executive_report,
    build_technical_report,
    build_compliance_report,
    # HTML rendering
    render_html_report,
    # PDF saving
    save_report_pdf,
    # Helpers
    _interval_for_period,
    _score_label,
    _score_color,
    _generate_recommendations,
    _build_finding_summaries,
    # Constants
    COLOR_PRIMARY,
    COLOR_ACCENT,
    COLOR_DARK,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_WARNING,
    PERIOD_TO_INTERVAL,
    # Main
    run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_data() -> dict:
    """Return empty aggregated data dict."""
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "score": 100.0}


def _mixed_vuln_data() -> dict:
    return {"critical": 3, "high": 5, "medium": 10, "low": 20, "total": 38, "score": 25.0}


def _mixed_soc_data() -> dict:
    return {"critical": 1, "high": 3, "medium": 8, "low": 12, "total": 24, "score": 37.0}


def _mixed_cloud_data() -> dict:
    return {
        "pass_count": 80, "fail_count": 20, "critical": 2, "high": 5,
        "medium": 8, "low": 5, "total": 100, "score": 60.0,
    }


def _mixed_darkweb_data() -> dict:
    return {"breach_count": 4, "critical": 1, "high": 2, "total_pwned": 5000, "score": 50.0}


def _mixed_secrets_data() -> dict:
    return {"critical": 2, "high": 4, "medium": 3, "low": 1, "total": 10, "score": 17.0}


def _make_report_data(**overrides) -> ReportData:
    defaults = dict(
        title="Test Client",
        subtitle="SIREN: 123456789",
        date="2025-01-15 10:00 UTC",
        period="last_7d",
        framework="nis2",
        overall_score=75.0,
        sections=[],
        finding_summaries=[],
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        recommendations=[],
    )
    defaults.update(overrides)
    return ReportData(**defaults)


def _make_report_data_with_findings() -> ReportData:
    return _make_report_data(
        overall_score=55.0,
        total_findings=72,
        critical_count=6,
        high_count=14,
        medium_count=29,
        low_count=23,
        finding_summaries=[
            FindingSummary("vuln-scan", "critical", 3, "3 vulns critiques"),
            FindingSummary("soc-monitor", "critical", 1, "1 alerte SOC critique"),
            FindingSummary("cloud-posture", "critical", 2, "2 ecarts cloud critiques"),
            FindingSummary("vuln-scan", "high", 5, "5 vulns elevees"),
            FindingSummary("soc-monitor", "high", 3, "3 alertes SOC elevees"),
            FindingSummary("cloud-posture", "high", 5, "5 ecarts cloud eleves"),
            FindingSummary("secrets", "high", 4, "4 secrets exposes"),
            FindingSummary("darkweb", "high", 2, "2 fuites dark web"),
            FindingSummary("vuln-scan", "medium", 10, "10 vulns moyennes"),
            FindingSummary("soc-monitor", "medium", 8, "8 alertes SOC moyennes"),
        ],
        recommendations=[
            "CRITIQUE : Corriger les vulns critiques",
            "CRITIQUE : Investiguer les alertes SOC critiques",
            "ELEVE : Revoquer les secrets",
            "MOYEN : Ameliorer la posture cloud",
            "MOYEN : Renforcer le MFA",
        ],
    )


# ---------------------------------------------------------------------------
# 1. ReportType enum tests
# ---------------------------------------------------------------------------

class TestReportTypeEnum:
    def test_executive_value(self):
        assert ReportType.EXECUTIVE.value == "executive"

    def test_technical_value(self):
        assert ReportType.TECHNICAL.value == "technical"

    def test_compliance_value(self):
        assert ReportType.COMPLIANCE.value == "compliance"

    def test_full_value(self):
        assert ReportType.FULL.value == "full"

    def test_all_members(self):
        members = {m.value for m in ReportType}
        assert members == {"executive", "technical", "compliance", "full"}


# ---------------------------------------------------------------------------
# 2. ReportFramework enum tests
# ---------------------------------------------------------------------------

class TestReportFrameworkEnum:
    def test_nis2_value(self):
        assert ReportFramework.NIS2.value == "nis2"

    def test_iso27001_value(self):
        assert ReportFramework.ISO27001.value == "iso27001"

    def test_both_value(self):
        assert ReportFramework.BOTH.value == "both"

    def test_all_members(self):
        members = {m.value for m in ReportFramework}
        assert members == {"nis2", "iso27001", "both"}


# ---------------------------------------------------------------------------
# 3. Data aggregation (mocked psql)
# ---------------------------------------------------------------------------

class TestDataAggregation:
    """Tests for the fetch_* functions with mocked _run_psql_query."""

    @pytest.mark.asyncio
    async def test_fetch_vuln_scan_summary(self):
        mock_result = [{"critical": 2, "high": 5, "medium": 10, "low": 3, "total": 20}]
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=mock_result):
            result = await fetch_vuln_scan_summary("last_7d")
        assert result["critical"] == 2
        assert result["high"] == 5
        assert result["total"] == 20
        assert "score" in result
        assert 0 <= result["score"] <= 100

    @pytest.mark.asyncio
    async def test_fetch_vuln_scan_empty(self):
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=[]):
            result = await fetch_vuln_scan_summary("last_30d")
        assert result["total"] == 0
        assert result["score"] == 100.0

    @pytest.mark.asyncio
    async def test_fetch_soc_alerts_summary(self):
        mock_result = [{"critical": 1, "high": 3, "medium": 5, "low": 8, "total": 17}]
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=mock_result):
            result = await fetch_soc_alerts_summary("last_7d")
        assert result["total"] == 17
        assert result["score"] <= 100
        assert result["score"] >= 0

    @pytest.mark.asyncio
    async def test_fetch_cloud_posture_summary(self):
        mock_result = [{"pass_count": 80, "fail_count": 20, "critical": 1, "high": 5, "medium": 10, "low": 4, "total": 100}]
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=mock_result):
            result = await fetch_cloud_posture_summary()
        assert result["score"] == 80.0  # 80/100 * 100
        assert result["total"] == 100

    @pytest.mark.asyncio
    async def test_fetch_cloud_posture_empty(self):
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=[]):
            result = await fetch_cloud_posture_summary()
        assert result["score"] == 100.0
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_fetch_darkweb_summary(self):
        mock_result = [{"breach_count": 3, "critical": 1, "high": 1, "total_pwned": 2000}]
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=mock_result):
            result = await fetch_darkweb_summary("last_30d")
        assert result["breach_count"] == 3
        assert "score" in result

    @pytest.mark.asyncio
    async def test_fetch_secrets_summary(self):
        mock_result = [{"critical": 1, "high": 2, "medium": 3, "low": 0, "total": 6}]
        with patch("src.main._run_psql_query", new_callable=AsyncMock, return_value=mock_result):
            result = await fetch_secrets_summary("last_quarter")
        assert result["total"] == 6
        assert "score" in result


# ---------------------------------------------------------------------------
# 4. Score calculation
# ---------------------------------------------------------------------------

class TestScoreCalculation:
    def test_perfect_score(self):
        """All data sources at 100 -> overall = 100."""
        score = calculate_overall_score(
            {"score": 100.0}, {"score": 100.0}, {"score": 100.0},
            {"score": 100.0}, {"score": 100.0},
        )
        assert score == 100.0

    def test_zero_score(self):
        """All data sources at 0 -> overall = 0."""
        score = calculate_overall_score(
            {"score": 0.0}, {"score": 0.0}, {"score": 0.0},
            {"score": 0.0}, {"score": 0.0},
        )
        assert score == 0.0

    def test_mixed_scores(self):
        """Weighted average of mixed scores."""
        score = calculate_overall_score(
            {"score": 50.0},   # vuln: 50 * 0.30 = 15
            {"score": 80.0},   # cloud: 80 * 0.25 = 20
            {"score": 60.0},   # soc: 60 * 0.20 = 12
            {"score": 70.0},   # secrets: 70 * 0.15 = 10.5
            {"score": 90.0},   # darkweb: 90 * 0.10 = 9
        )
        expected = 15.0 + 20.0 + 12.0 + 10.5 + 9.0  # 66.5
        assert score == expected

    def test_missing_data_defaults_to_100(self):
        """Missing score keys default to 100."""
        score = calculate_overall_score({}, {}, {}, {}, {})
        assert score == 100.0

    def test_score_clamped_to_0_100(self):
        """Score cannot exceed 100 or go below 0."""
        score_high = calculate_overall_score(
            {"score": 200.0}, {"score": 200.0}, {"score": 200.0},
            {"score": 200.0}, {"score": 200.0},
        )
        assert score_high == 100.0

        score_low = calculate_overall_score(
            {"score": -50.0}, {"score": -50.0}, {"score": -50.0},
            {"score": -50.0}, {"score": -50.0},
        )
        assert score_low == 0.0

    def test_weights_sum_to_one(self):
        """Ensure all weights add up to 1.0."""
        total = sum(SCORE_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# 5. Executive report content
# ---------------------------------------------------------------------------

class TestBuildExecutiveReport:
    def test_contains_french_text(self):
        data = _make_report_data_with_findings()
        html = build_executive_report(data)
        assert "Synth\u00e8se ex\u00e9cutive" in html
        assert "Score de s\u00e9curit\u00e9 global" in html
        assert "Recommandations prioritaires" in html

    def test_contains_all_sections(self):
        data = _make_report_data_with_findings()
        html = build_executive_report(data)
        assert 'id="synthese"' in html
        assert 'id="score-global"' in html
        assert 'id="top-risques"' in html
        assert 'id="evolution"' in html
        assert 'id="recommandations"' in html

    def test_score_displayed(self):
        data = _make_report_data(overall_score=72.0)
        html = build_executive_report(data)
        assert "72/100" in html

    def test_critical_findings_listed(self):
        data = _make_report_data_with_findings()
        html = build_executive_report(data)
        assert "vuln-scan" in html
        assert "3 vulns critiques" in html

    def test_recommendations_listed(self):
        data = _make_report_data(recommendations=["Rec 1", "Rec 2"])
        html = build_executive_report(data)
        assert "Rec 1" in html
        assert "Rec 2" in html

    def test_no_critical_findings(self):
        data = _make_report_data()
        html = build_executive_report(data)
        assert "Aucun risque critique" in html


# ---------------------------------------------------------------------------
# 6. Technical report content
# ---------------------------------------------------------------------------

class TestBuildTechnicalReport:
    def test_contains_sections(self):
        data = _make_report_data_with_findings()
        html = build_technical_report(data)
        assert 'id="tech-overview"' in html
        assert 'id="findings-par-categorie"' in html
        assert 'id="analyse-soc"' in html
        assert 'id="posture-cloud"' in html

    def test_severity_badges(self):
        data = _make_report_data_with_findings()
        html = build_technical_report(data)
        assert "CRITICAL" in html
        assert "HIGH" in html

    def test_grouped_by_source(self):
        data = _make_report_data_with_findings()
        html = build_technical_report(data)
        assert "vuln-scan" in html
        assert "soc-monitor" in html
        assert "cloud-posture" in html

    def test_empty_findings(self):
        data = _make_report_data()
        html = build_technical_report(data)
        assert "Aucun finding" in html


# ---------------------------------------------------------------------------
# 7. Compliance report content
# ---------------------------------------------------------------------------

class TestBuildComplianceReport:
    def test_nis2_sections(self):
        data = _make_report_data_with_findings()
        html = build_compliance_report(data, "NIS2")
        assert "NIS2" in html
        assert "Art.21" in html
        assert "Directive (UE) 2022/2555" in html

    def test_iso_sections(self):
        data = _make_report_data_with_findings()
        html = build_compliance_report(data, "ISO27001")
        assert "ISO 27001" in html
        assert "Annexe A" in html
        assert "A.5" in html
        assert "A.18" in html

    def test_both_frameworks(self):
        data = _make_report_data_with_findings()
        html = build_compliance_report(data, "BOTH")
        assert "NIS2" in html
        assert "ISO 27001" in html

    def test_gap_analysis_section(self):
        data = _make_report_data_with_findings()
        html = build_compliance_report(data, "NIS2")
        assert 'id="gap-analysis"' in html
        assert "\u00e9carts identifi\u00e9s" in html

    def test_plan_action_section(self):
        data = _make_report_data(recommendations=["Action 1", "Action 2"])
        html = build_compliance_report(data, "NIS2")
        assert 'id="plan-action"' in html
        assert "Action 1" in html

    def test_no_gaps(self):
        data = _make_report_data(total_findings=0)
        html = build_compliance_report(data, "NIS2")
        assert "Posture de conformit\u00e9 satisfaisante" in html


# ---------------------------------------------------------------------------
# 8. HTML rendering
# ---------------------------------------------------------------------------

class TestRenderHtmlReport:
    def test_css_present(self):
        data = _make_report_data()
        html = render_html_report(data, "executive", "nis2")
        assert "<style>" in html
        assert COLOR_PRIMARY in html
        assert COLOR_ACCENT in html
        assert COLOR_DARK in html

    def test_header_present(self):
        data = _make_report_data(title="ACME Corp", date="2025-01-15 10:00 UTC")
        html = render_html_report(data, "executive", "nis2")
        assert "ThreatClaw" in html
        assert "ACME Corp" in html
        assert "2025-01-15" in html

    def test_footer_present(self):
        data = _make_report_data()
        html = render_html_report(data, "executive", "nis2")
        assert "CONFIDENTIEL" in html
        assert "destinataires autoris\u00e9s" in html

    def test_toc_present(self):
        data = _make_report_data()
        html = render_html_report(data, "executive", "nis2")
        assert 'id="toc"' in html
        assert "Table des mati\u00e8res" in html

    def test_executive_sections_in_toc(self):
        data = _make_report_data()
        html = render_html_report(data, "executive", "nis2")
        assert 'href="#synthese"' in html
        assert 'href="#recommandations"' in html

    def test_full_report_all_sections(self):
        data = _make_report_data_with_findings()
        html = render_html_report(data, "full", "both")
        # Executive sections
        assert 'id="synthese"' in html
        # Technical sections
        assert 'id="tech-overview"' in html
        # Compliance sections
        assert 'id="compliance-score"' in html
        assert 'id="gap-analysis"' in html

    def test_compliance_report_type(self):
        data = _make_report_data()
        html = render_html_report(data, "compliance", "iso27001")
        assert "Conformit\u00e9 ISO27001" in html

    def test_valid_html_structure(self):
        data = _make_report_data()
        html = render_html_report(data, "executive", "nis2")
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert '<html lang="fr">' in html


# ---------------------------------------------------------------------------
# 9. Full run pipeline (mocked DB)
# ---------------------------------------------------------------------------

class TestRunPipeline:
    @pytest.mark.asyncio
    async def test_full_run_default_input(self):
        """Full run with mocked DB returns success."""
        empty = _empty_data()
        with patch("src.main.fetch_vuln_scan_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_soc_alerts_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_cloud_posture_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_darkweb_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_secrets_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.save_report_pdf", new_callable=AsyncMock, return_value="/tmp/test.html"):
            output = await run(SkillInput())
        assert output.success is True
        assert output.error is None
        assert output.report_data is not None
        assert output.report_data.overall_score == 100.0

    @pytest.mark.asyncio
    async def test_full_run_with_findings(self):
        """Full run with mixed data produces correct counts."""
        with patch("src.main.fetch_vuln_scan_summary", new_callable=AsyncMock, return_value=_mixed_vuln_data()), \
             patch("src.main.fetch_soc_alerts_summary", new_callable=AsyncMock, return_value=_mixed_soc_data()), \
             patch("src.main.fetch_cloud_posture_summary", new_callable=AsyncMock, return_value=_mixed_cloud_data()), \
             patch("src.main.fetch_darkweb_summary", new_callable=AsyncMock, return_value=_mixed_darkweb_data()), \
             patch("src.main.fetch_secrets_summary", new_callable=AsyncMock, return_value=_mixed_secrets_data()), \
             patch("src.main.save_report_pdf", new_callable=AsyncMock, return_value="/tmp/report.html"):
            output = await run(SkillInput(
                report_type=ReportType.FULL,
                period="last_30d",
                framework=ReportFramework.BOTH,
                client_name="ACME Corp",
                client_siren="123456789",
            ))
        assert output.success is True
        assert output.report_data is not None
        assert output.report_data.total_findings > 0
        assert output.report_data.critical_count > 0
        assert output.report_data.overall_score < 100.0
        assert "ACME Corp" in output.html_content
        assert len(output.summary) > 0

    @pytest.mark.asyncio
    async def test_run_technical_report(self):
        """Run with technical report type."""
        empty = _empty_data()
        with patch("src.main.fetch_vuln_scan_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_soc_alerts_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_cloud_posture_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_darkweb_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_secrets_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.save_report_pdf", new_callable=AsyncMock, return_value="/tmp/tech.html"):
            output = await run(SkillInput(report_type=ReportType.TECHNICAL))
        assert output.success is True
        assert "tech-overview" in output.html_content

    @pytest.mark.asyncio
    async def test_run_compliance_report(self):
        """Run with compliance report type."""
        empty = _empty_data()
        with patch("src.main.fetch_vuln_scan_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_soc_alerts_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_cloud_posture_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_darkweb_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_secrets_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.save_report_pdf", new_callable=AsyncMock, return_value="/tmp/comp.html"):
            output = await run(SkillInput(
                report_type=ReportType.COMPLIANCE,
                framework=ReportFramework.ISO27001,
            ))
        assert output.success is True
        assert "compliance-score" in output.html_content

    @pytest.mark.asyncio
    async def test_run_handles_db_error(self):
        """Run gracefully handles database errors."""
        empty = _empty_data()
        with patch("src.main.fetch_vuln_scan_summary", new_callable=AsyncMock, side_effect=RuntimeError("DB down")), \
             patch("src.main.fetch_soc_alerts_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_cloud_posture_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_darkweb_summary", new_callable=AsyncMock, return_value=empty), \
             patch("src.main.fetch_secrets_summary", new_callable=AsyncMock, return_value=empty):
            output = await run(SkillInput())
        assert output.success is False
        assert "DB down" in output.error


# ---------------------------------------------------------------------------
# 10. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_data_report(self):
        """Report with no findings should render correctly."""
        data = _make_report_data()
        html = build_executive_report(data)
        assert "0" in html or "Aucun" in html

    def test_unknown_framework_compliance(self):
        """Compliance report with unknown framework renders without NIS2/ISO blocks."""
        data = _make_report_data()
        html = build_compliance_report(data, "UNKNOWN")
        # Should still produce valid HTML -- neither NIS2 nor ISO sections shown
        assert 'id="gap-analysis"' in html
        assert "Art.21" not in html
        assert "A.5" not in html

    def test_interval_for_period_known(self):
        assert _interval_for_period("last_7d") == "7 days"
        assert _interval_for_period("last_30d") == "30 days"
        assert _interval_for_period("last_quarter") == "90 days"

    def test_interval_for_period_unknown(self):
        assert _interval_for_period("unknown_period") == "7 days"

    def test_score_label(self):
        assert _score_label(85) == "Bon"
        assert _score_label(65) == "Acceptable"
        assert _score_label(45) == "Insuffisant"
        assert _score_label(20) == "Critique"

    def test_score_color(self):
        assert _score_color(85) == COLOR_SUCCESS
        assert _score_color(65) == COLOR_WARNING
        assert _score_color(30) == COLOR_DANGER

    def test_no_findings_no_recommendations(self):
        recs = _generate_recommendations(
            _empty_data(), _empty_data(), _empty_data(),
            _empty_data(), _empty_data(),
        )
        assert len(recs) >= 1
        assert "Maintenir" in recs[0]

    def test_finding_summaries_empty(self):
        summaries = _build_finding_summaries(
            _empty_data(), _empty_data(), _empty_data(),
            _empty_data(), _empty_data(),
        )
        assert summaries == []

    def test_finding_summaries_sorted_by_severity(self):
        summaries = _build_finding_summaries(
            {"critical": 0, "high": 0, "medium": 5, "low": 0, "total": 5, "score": 90.0},
            _empty_data(),
            {"critical": 2, "high": 0, "medium": 0, "low": 0, "total": 2, "score": 80.0},
            _empty_data(),
            _empty_data(),
        )
        # First entry should be critical (from SOC, but cloud has critical)
        assert summaries[0].severity == "critical"
        assert summaries[-1].severity == "medium"


# ---------------------------------------------------------------------------
# 11. ReportData serialization
# ---------------------------------------------------------------------------

class TestReportDataSerialization:
    def test_to_dict(self):
        data = _make_report_data(
            overall_score=72.5,
            total_findings=10,
            finding_summaries=[
                FindingSummary("vuln-scan", "critical", 3, "3 vulns"),
            ],
        )
        d = data.to_dict()
        assert d["overall_score"] == 72.5
        assert d["total_findings"] == 10
        assert len(d["finding_summaries"]) == 1
        assert d["finding_summaries"][0]["source_skill"] == "vuln-scan"

    def test_finding_summary_to_dict(self):
        fs = FindingSummary("soc-monitor", "high", 5, "5 alertes")
        d = fs.to_dict()
        assert d == {
            "source_skill": "soc-monitor",
            "severity": "high",
            "count": 5,
            "description": "5 alertes",
        }

    def test_report_section_to_dict(self):
        sec = ReportSection(
            title="Test",
            content="Content here",
            score=85.0,
            findings_count=3,
            severity_breakdown={"critical": 1, "high": 2},
        )
        d = sec.to_dict()
        assert d["title"] == "Test"
        assert d["score"] == 85.0
        assert d["severity_breakdown"]["critical"] == 1

    def test_full_report_data_json_serializable(self):
        """Ensure the full ReportData can be serialized to JSON."""
        data = _make_report_data_with_findings()
        d = data.to_dict()
        json_str = json.dumps(d, ensure_ascii=False)
        parsed = json.loads(json_str)
        assert parsed["title"] == "Test Client"
        assert parsed["overall_score"] == 55.0

    def test_skill_output_with_report_data(self):
        data = _make_report_data(overall_score=80.0)
        output = SkillOutput(
            success=True,
            pdf_path="/tmp/report.html",
            html_content="<html></html>",
            report_data=data,
            summary="Test summary",
        )
        assert output.success is True
        assert output.report_data.overall_score == 80.0


# ---------------------------------------------------------------------------
# 12. PDF save stub
# ---------------------------------------------------------------------------

class TestSaveReportPdf:
    @pytest.mark.asyncio
    async def test_save_creates_html_file(self, tmp_path):
        html_content = "<html><body>Test</body></html>"
        output_path = str(tmp_path / "report.pdf")
        result = await save_report_pdf(html_content, output_path)
        assert result.endswith(".html")
        # Verify file was created
        with open(result) as f:
            content = f.read()
        assert content == html_content

    @pytest.mark.asyncio
    async def test_save_creates_directory(self, tmp_path):
        output_path = str(tmp_path / "subdir" / "report.pdf")
        result = await save_report_pdf("<html></html>", output_path)
        assert result.endswith(".html")


# ---------------------------------------------------------------------------
# 13. SkillInput defaults
# ---------------------------------------------------------------------------

class TestSkillInputDefaults:
    def test_default_values(self):
        si = SkillInput()
        assert si.report_type == ReportType.EXECUTIVE
        assert si.period == "last_7d"
        assert si.framework == ReportFramework.NIS2
        assert si.language == "fr"
        assert si.include_sections == ["all"]
        assert si.client_name == ""
        assert si.client_siren == ""

    def test_custom_values(self):
        si = SkillInput(
            report_type=ReportType.FULL,
            period="last_quarter",
            framework=ReportFramework.BOTH,
            language="en",
            client_name="ACME",
            client_siren="999888777",
        )
        assert si.report_type == ReportType.FULL
        assert si.client_name == "ACME"
        assert si.client_siren == "999888777"
