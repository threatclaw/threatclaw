"""
skill-vuln-scan — Vulnerability scanning orchestrator
Nuclei (network CVEs) + Grype (image CVEs) + EPSS/NVD enrichment

This module provides the business logic for vulnerability scanning.
It is invoked by the ThreatClaw core via the WASM sandbox.
"""

import json
import subprocess
import asyncio
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


# ── Constants ──────────────────────────────────────────────

EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NUCLEI_RATE_LIMIT = 100  # requests/second
NUCLEI_TIMEOUT = 300  # seconds
GRYPE_TIMEOUT = 120  # seconds


# ── Data Models ────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "negligible": cls.INFO,
            "unknown": cls.INFO,
        }
        return mapping.get(s.lower(), cls.INFO)


class ScanType(Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


@dataclass
class Finding:
    cve_id: str
    title: str
    severity: Severity
    cvss_score: float
    epss_score: float
    priority_score: float  # cvss * epss — real-world priority
    source: str  # "nuclei" | "grype"
    target: str
    description: str
    remediation: str = ""
    matched_at: str = ""
    template_id: str = ""  # nuclei template
    package_name: str = ""  # grype package
    installed_version: str = ""
    fixed_version: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    targets_scanned: list[str] = field(default_factory=list)
    images_scanned: list[str] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_start: str = ""
    scan_end: str = ""
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class SkillInput:
    targets: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    scan_type: ScanType = ScanType.QUICK
    templates: list[str] = field(default_factory=list)
    severity_filter: list[str] = field(
        default_factory=lambda: ["critical", "high", "medium"]
    )


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ScanResult] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "result": self.result.to_dict() if self.result else None,
            "error": self.error,
        }


# ── Nuclei Scanner ─────────────────────────────────────────

def _build_nuclei_cmd(
    target: str,
    scan_type: ScanType,
    severity_filter: list[str],
    templates: list[str],
) -> list[str]:
    """Build Nuclei command line arguments."""
    cmd = [
        "docker", "exec", "nuclei",
        "nuclei",
        "-u", target,
        "-json",
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-timeout", "10",
        "-retries", "1",
        "-silent",
    ]

    if severity_filter:
        cmd.extend(["-severity", ",".join(severity_filter)])

    if scan_type == ScanType.QUICK:
        cmd.extend(["-tags", "cve,rce,sqli,xss,lfi"])
    elif scan_type == ScanType.CUSTOM and templates:
        for t in templates:
            cmd.extend(["-t", t])

    return cmd


def _parse_nuclei_finding(line: str, target: str) -> Optional[Finding]:
    """Parse a single Nuclei JSON output line into a Finding."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = data.get("info", {})
    severity_str = info.get("severity", "info")
    cve_ids = info.get("classification", {}).get("cve-id", [])
    cve_id = cve_ids[0] if cve_ids else data.get("template-id", "N/A")

    cvss_score = 0.0
    cvss_metrics = info.get("classification", {}).get("cvss-score", None)
    if cvss_metrics:
        try:
            cvss_score = float(cvss_metrics)
        except (ValueError, TypeError):
            pass

    return Finding(
        cve_id=cve_id,
        title=info.get("name", "Unknown"),
        severity=Severity.from_string(severity_str),
        cvss_score=cvss_score,
        epss_score=0.0,
        priority_score=0.0,
        source="nuclei",
        target=target,
        description=info.get("description", ""),
        remediation=info.get("remediation", ""),
        matched_at=data.get("matched-at", ""),
        template_id=data.get("template-id", ""),
        timestamp=data.get("timestamp", ""),
    )


async def run_nuclei_scan(
    targets: list[str],
    scan_type: ScanType,
    severity_filter: list[str],
    templates: list[str],
) -> list[Finding]:
    """Run Nuclei scan against network targets."""
    findings: list[Finding] = []

    for target in targets:
        cmd = _build_nuclei_cmd(target, scan_type, severity_filter, templates)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=NUCLEI_TIMEOUT
            )

            for line in stdout.decode("utf-8", errors="replace").strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                finding = _parse_nuclei_finding(line, target)
                if finding:
                    findings.append(finding)

        except asyncio.TimeoutError:
            findings.append(
                Finding(
                    cve_id="SCAN-TIMEOUT",
                    title=f"Nuclei scan timeout for {target}",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    epss_score=0.0,
                    priority_score=0.0,
                    source="nuclei",
                    target=target,
                    description=f"Scan exceeded {NUCLEI_TIMEOUT}s timeout",
                )
            )
        except FileNotFoundError:
            raise RuntimeError(
                "Docker not found. Ensure Nuclei container is running."
            )

    return findings


# ── Grype Scanner ──────────────────────────────────────────

def _parse_grype_output(output: str, image: str) -> list[Finding]:
    """Parse Grype JSON output into Findings."""
    findings: list[Finding] = []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return findings

    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cve_id = vuln.get("id", "UNKNOWN")
        severity_str = vuln.get("severity", "Unknown")

        cvss_score = 0.0
        for cvss in vuln.get("cvss", []):
            metrics = cvss.get("metrics", {})
            score = metrics.get("baseScore", 0.0)
            if score > cvss_score:
                cvss_score = score

        fixed_versions = vuln.get("fix", {}).get("versions", [])
        fixed_version = fixed_versions[0] if fixed_versions else ""

        findings.append(
            Finding(
                cve_id=cve_id,
                title=f"{cve_id} in {artifact.get('name', 'unknown')}",
                severity=Severity.from_string(severity_str),
                cvss_score=cvss_score,
                epss_score=0.0,
                priority_score=0.0,
                source="grype",
                target=image,
                description=vuln.get("description", ""),
                package_name=artifact.get("name", ""),
                installed_version=artifact.get("version", ""),
                fixed_version=fixed_version,
            )
        )

    return findings


async def run_grype_scan(images: list[str]) -> list[Finding]:
    """Run Grype scan against Docker images."""
    findings: list[Finding] = []

    for image in images:
        cmd = [
            "docker", "exec", "grype",
            "grype", image, "-o", "json", "--quiet",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=GRYPE_TIMEOUT
            )

            image_findings = _parse_grype_output(
                stdout.decode("utf-8", errors="replace"), image
            )
            findings.extend(image_findings)

        except asyncio.TimeoutError:
            findings.append(
                Finding(
                    cve_id="SCAN-TIMEOUT",
                    title=f"Grype scan timeout for {image}",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    epss_score=0.0,
                    priority_score=0.0,
                    source="grype",
                    target=image,
                    description=f"Scan exceeded {GRYPE_TIMEOUT}s timeout",
                )
            )
        except FileNotFoundError:
            raise RuntimeError(
                "Docker not found. Ensure Grype container is running."
            )

    return findings


# ── EPSS Enrichment ────────────────────────────────────────

async def enrich_with_epss(
    findings: list[Finding], http_get=None
) -> list[Finding]:
    """
    Enrich findings with EPSS scores from FIRST API.
    http_get: async callable(url) -> dict (injected for testability)
    """
    cve_ids = list(set(
        f.cve_id for f in findings
        if f.cve_id.startswith("CVE-")
    ))

    if not cve_ids:
        return findings

    epss_map: dict[str, float] = {}

    # Batch CVEs in groups of 30 (API limit)
    batch_size = 30
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        cve_param = ",".join(batch)
        url = f"{EPSS_API_URL}?cve={cve_param}"

        try:
            if http_get:
                data = await http_get(url)
            else:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-f", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=30
                )
                data = json.loads(stdout.decode("utf-8"))

            for entry in data.get("data", []):
                cve = entry.get("cve", "")
                epss = float(entry.get("epss", 0.0))
                epss_map[cve] = epss

        except Exception:
            # EPSS enrichment is best-effort
            continue

    for f in findings:
        if f.cve_id in epss_map:
            f.epss_score = epss_map[f.cve_id]
        f.priority_score = round(f.cvss_score * f.epss_score, 4)

    return findings


# ── Priority Sorting ───────────────────────────────────────

def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by priority score (CVSS * EPSS) descending.
    Falls back to CVSS alone if EPSS is unavailable."""
    return sorted(
        findings,
        key=lambda f: (f.priority_score, f.cvss_score),
        reverse=True,
    )


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate CVEs, keeping the highest severity instance."""
    seen: dict[str, Finding] = {}
    for f in findings:
        key = f"{f.cve_id}:{f.target}"
        if key not in seen or f.cvss_score > seen[key].cvss_score:
            seen[key] = f
    return list(seen.values())


# ── Main Entry Point ───────────────────────────────────────

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point — orchestrates full vulnerability scan."""
    if not input.targets and not input.images:
        return SkillOutput(
            success=False,
            error="Aucune cible fournie. Spécifiez des targets (IPs/domaines) ou des images Docker.",
        )

    start_time = datetime.now(timezone.utc)

    try:
        all_findings: list[Finding] = []

        # Run scans in parallel
        tasks = []
        if input.targets:
            tasks.append(
                run_nuclei_scan(
                    input.targets,
                    input.scan_type,
                    input.severity_filter,
                    input.templates,
                )
            )
        if input.images:
            tasks.append(run_grype_scan(input.images))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                return SkillOutput(
                    success=False,
                    error=f"Erreur de scan : {result}",
                )
            all_findings.extend(result)

        # Deduplicate
        all_findings = deduplicate_findings(all_findings)

        # Enrich with EPSS scores
        all_findings = await enrich_with_epss(all_findings)

        # Prioritize
        all_findings = prioritize_findings(all_findings)

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Count by severity
        counts = {s: 0 for s in Severity}
        for f in all_findings:
            counts[f.severity] += 1

        result = ScanResult(
            findings=all_findings,
            targets_scanned=input.targets,
            images_scanned=input.images,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
            scan_start=start_time.isoformat(),
            scan_end=end_time.isoformat(),
            scan_duration_seconds=round(duration, 2),
            summary=(
                f"Scan terminé en {duration:.0f}s — "
                f"{len(all_findings)} vulnérabilités trouvées "
                f"({counts[Severity.CRITICAL]} critiques, "
                f"{counts[Severity.HIGH]} élevées, "
                f"{counts[Severity.MEDIUM]} moyennes)"
            ),
        )

        return SkillOutput(success=True, result=result)

    except Exception as e:
        return SkillOutput(success=False, error=f"Erreur inattendue : {e}")
