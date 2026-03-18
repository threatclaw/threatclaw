"""
skill-appsec — Application security scanning
Trivy (containers/deps) + Semgrep (SAST)
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AppSecFinding:
    tool: str  # "trivy" | "semgrep"
    severity: str
    title: str
    file_path: str = ""
    line: int = 0
    cve_id: str = ""
    package: str = ""
    fixed_version: str = ""
    description: str = ""


@dataclass
class SkillInput:
    repositories: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    scan_code: bool = True


@dataclass
class SkillOutput:
    success: bool = False
    findings: list[AppSecFinding] = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None


async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    try:
        # TODO: Call Trivy server API and Semgrep CLI
        return SkillOutput(success=True, summary="Scan AppSec terminé")
    except Exception as e:
        return SkillOutput(success=False, error=str(e))
