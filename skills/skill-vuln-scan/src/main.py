"""
skill-vuln-scan — Vulnerability scanning orchestrator
Nuclei (network CVEs) + Grype (image CVEs) + EPSS scoring
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ScanType(Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    cve_id: str
    title: str
    severity: Severity
    cvss_score: float
    epss_score: float
    priority_score: float  # cvss * epss
    source: str  # "nuclei" | "grype"
    target: str
    description: str
    remediation: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_duration_seconds: float = 0.0


@dataclass
class SkillInput:
    targets: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    scan_type: ScanType = ScanType.QUICK
    templates: list[str] = field(default_factory=list)


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ScanResult] = None
    error: Optional[str] = None


async def run_nuclei_scan(targets: list[str], scan_type: ScanType) -> list[Finding]:
    """Run Nuclei scan against network targets."""
    # TODO: Implement Nuclei API call via HTTP
    # POST http://nuclei:8080/scan
    return []


async def run_grype_scan(images: list[str]) -> list[Finding]:
    """Run Grype scan against Docker images."""
    # TODO: Implement Grype CLI invocation
    return []


async def enrich_with_epss(findings: list[Finding]) -> list[Finding]:
    """Enrich findings with EPSS scores from FIRST API."""
    # TODO: GET https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX
    for f in findings:
        f.priority_score = f.cvss_score * f.epss_score
    return findings


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by priority score (CVSS * EPSS) descending."""
    return sorted(findings, key=lambda f: f.priority_score, reverse=True)


async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    try:
        all_findings: list[Finding] = []

        if input.targets:
            nuclei_findings = await run_nuclei_scan(input.targets, input.scan_type)
            all_findings.extend(nuclei_findings)

        if input.images:
            grype_findings = await run_grype_scan(input.images)
            all_findings.extend(grype_findings)

        all_findings = await enrich_with_epss(all_findings)
        all_findings = prioritize_findings(all_findings)

        result = ScanResult(
            findings=all_findings,
            critical_count=sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in all_findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in all_findings if f.severity == Severity.LOW),
            summary=f"Scan terminé : {len(all_findings)} vulnérabilités trouvées",
        )

        return SkillOutput(success=True, result=result)

    except Exception as e:
        return SkillOutput(success=False, error=str(e))
