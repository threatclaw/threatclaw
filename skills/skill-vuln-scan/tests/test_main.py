"""Tests for skill-vuln-scan."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.main import (
    Finding,
    Severity,
    ScanType,
    SkillInput,
    ScanResult,
    _parse_nuclei_finding,
    _parse_grype_output,
    prioritize_findings,
    deduplicate_findings,
    enrich_with_epss,
    run,
)


# ── Severity Tests ──────────────────────────────────────

class TestSeverity:
    def test_from_string_valid(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM
        assert Severity.from_string("low") == Severity.LOW

    def test_from_string_unknown(self):
        assert Severity.from_string("unknown") == Severity.INFO
        assert Severity.from_string("negligible") == Severity.INFO
        assert Severity.from_string("garbage") == Severity.INFO


# ── Nuclei Parser Tests ────────────────────────────────

class TestNucleiParser:
    def test_parse_valid_finding(self):
        nuclei_json = json.dumps({
            "template-id": "CVE-2021-44228-log4j",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "description": "Remote code execution via Log4j",
                "remediation": "Upgrade to Log4j 2.17.0+",
                "classification": {
                    "cve-id": ["CVE-2021-44228"],
                    "cvss-score": 10.0,
                },
            },
            "matched-at": "https://target.com:443",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        finding = _parse_nuclei_finding(nuclei_json, "target.com")
        assert finding is not None
        assert finding.cve_id == "CVE-2021-44228"
        assert finding.severity == Severity.CRITICAL
        assert finding.cvss_score == 10.0
        assert finding.source == "nuclei"
        assert finding.target == "target.com"
        assert "Log4j" in finding.title

    def test_parse_finding_without_cve(self):
        nuclei_json = json.dumps({
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "medium",
            },
            "matched-at": "http://target.com/admin",
        })
        finding = _parse_nuclei_finding(nuclei_json, "target.com")
        assert finding is not None
        assert finding.cve_id == "exposed-panel"

    def test_parse_invalid_json(self):
        assert _parse_nuclei_finding("not json", "target") is None

    def test_parse_empty_line(self):
        assert _parse_nuclei_finding("", "target") is None


# ── Grype Parser Tests ─────────────────────────────────

class TestGrypeParser:
    def test_parse_valid_output(self):
        grype_json = json.dumps({
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-44487",
                        "severity": "High",
                        "description": "HTTP/2 Rapid Reset Attack",
                        "cvss": [
                            {"metrics": {"baseScore": 7.5}},
                        ],
                        "fix": {"versions": ["1.2.3"]},
                    },
                    "artifact": {
                        "name": "golang.org/x/net",
                        "version": "0.7.0",
                    },
                },
                {
                    "vulnerability": {
                        "id": "CVE-2023-99999",
                        "severity": "Critical",
                        "description": "Test vuln",
                        "cvss": [
                            {"metrics": {"baseScore": 9.8}},
                        ],
                        "fix": {"versions": []},
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1",
                    },
                },
            ]
        })
        findings = _parse_grype_output(grype_json, "nginx:latest")
        assert len(findings) == 2

        f1 = findings[0]
        assert f1.cve_id == "CVE-2023-44487"
        assert f1.severity == Severity.HIGH
        assert f1.cvss_score == 7.5
        assert f1.package_name == "golang.org/x/net"
        assert f1.installed_version == "0.7.0"
        assert f1.fixed_version == "1.2.3"
        assert f1.source == "grype"
        assert f1.target == "nginx:latest"

        f2 = findings[1]
        assert f2.fixed_version == ""

    def test_parse_empty_matches(self):
        result = _parse_grype_output('{"matches": []}', "img")
        assert len(result) == 0

    def test_parse_invalid_json(self):
        result = _parse_grype_output("not json", "img")
        assert len(result) == 0


# ── Priority & Dedup Tests ─────────────────────────────

def _make_finding(cve_id: str, cvss: float, epss: float, target: str = "t") -> Finding:
    return Finding(
        cve_id=cve_id,
        title=cve_id,
        severity=Severity.CRITICAL if cvss >= 9 else Severity.HIGH,
        cvss_score=cvss,
        epss_score=epss,
        priority_score=round(cvss * epss, 4),
        source="nuclei",
        target=target,
        description="test",
    )


class TestPrioritize:
    def test_sort_by_priority(self):
        findings = [
            _make_finding("CVE-1", 3.0, 0.01),   # priority=0.03
            _make_finding("CVE-2", 9.8, 0.95),   # priority=9.31
            _make_finding("CVE-3", 7.5, 0.50),   # priority=3.75
        ]
        result = prioritize_findings(findings)
        assert result[0].cve_id == "CVE-2"
        assert result[1].cve_id == "CVE-3"
        assert result[2].cve_id == "CVE-1"

    def test_fallback_to_cvss_when_epss_equal(self):
        findings = [
            _make_finding("CVE-A", 7.0, 0.0),
            _make_finding("CVE-B", 9.0, 0.0),
        ]
        result = prioritize_findings(findings)
        assert result[0].cve_id == "CVE-B"

    def test_empty_list(self):
        assert prioritize_findings([]) == []


class TestDeduplicate:
    def test_removes_duplicates(self):
        findings = [
            _make_finding("CVE-1", 7.0, 0.5, "target1"),
            _make_finding("CVE-1", 9.0, 0.5, "target1"),  # same CVE+target, higher CVSS
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].cvss_score == 9.0

    def test_keeps_different_targets(self):
        findings = [
            _make_finding("CVE-1", 7.0, 0.5, "target1"),
            _make_finding("CVE-1", 7.0, 0.5, "target2"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2


# ── EPSS Enrichment Tests ──────────────────────────────

class TestEPSSEnrichment:
    @pytest.mark.asyncio
    async def test_enriches_findings(self):
        findings = [
            _make_finding("CVE-2021-44228", 10.0, 0.0),
            _make_finding("CVE-2023-44487", 7.5, 0.0),
        ]

        async def mock_http_get(url):
            return {
                "data": [
                    {"cve": "CVE-2021-44228", "epss": "0.975"},
                    {"cve": "CVE-2023-44487", "epss": "0.234"},
                ]
            }

        result = await enrich_with_epss(findings, http_get=mock_http_get)
        assert result[0].epss_score == 0.975
        assert result[0].priority_score == round(10.0 * 0.975, 4)
        assert result[1].epss_score == 0.234

    @pytest.mark.asyncio
    async def test_skips_non_cve_ids(self):
        findings = [
            _make_finding("exposed-panel", 5.0, 0.0),
        ]
        # Should not call API at all
        result = await enrich_with_epss(findings, http_get=None)
        assert result[0].epss_score == 0.0

    @pytest.mark.asyncio
    async def test_handles_api_error(self):
        findings = [_make_finding("CVE-2021-44228", 10.0, 0.0)]

        async def mock_http_error(url):
            raise ConnectionError("API down")

        result = await enrich_with_epss(findings, http_get=mock_http_error)
        assert result[0].epss_score == 0.0  # graceful degradation


# ── Main Run Tests ─────────────────────────────────────

class TestRun:
    @pytest.mark.asyncio
    async def test_run_no_targets(self):
        output = await run(SkillInput())
        assert output.success is False
        assert "cible" in output.error.lower()

    @pytest.mark.asyncio
    async def test_finding_to_dict(self):
        f = _make_finding("CVE-1", 9.0, 0.5)
        d = f.to_dict()
        assert d["severity"] == "critical"
        assert d["cvss_score"] == 9.0

    def test_scan_result_counts(self):
        result = ScanResult(
            findings=[
                _make_finding("CVE-1", 9.8, 0.9),
                _make_finding("CVE-2", 7.0, 0.3),
            ],
            critical_count=1,
            high_count=1,
        )
        assert result.critical_count == 1
        assert result.high_count == 1
