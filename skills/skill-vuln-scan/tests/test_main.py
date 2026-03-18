"""Tests for skill-vuln-scan."""

import pytest
from src.main import (
    Finding,
    Severity,
    SkillInput,
    ScanType,
    prioritize_findings,
    run,
)


def test_prioritize_findings():
    findings = [
        Finding(
            cve_id="CVE-2024-0001",
            title="Low priority",
            severity=Severity.LOW,
            cvss_score=3.0,
            epss_score=0.01,
            priority_score=0.03,
            source="nuclei",
            target="192.168.1.1",
            description="Test",
        ),
        Finding(
            cve_id="CVE-2024-0002",
            title="High priority",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            epss_score=0.95,
            priority_score=9.31,
            source="nuclei",
            target="192.168.1.1",
            description="Test",
        ),
    ]
    result = prioritize_findings(findings)
    assert result[0].cve_id == "CVE-2024-0002"
    assert result[1].cve_id == "CVE-2024-0001"


@pytest.mark.asyncio
async def test_run_empty_input():
    input = SkillInput()
    output = await run(input)
    assert output.success is True
    assert output.result is not None
    assert len(output.result.findings) == 0
