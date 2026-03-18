"""
skill-secrets — Secret & credential detection
Gitleaks for Git repositories + paste site monitoring
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SecretType(Enum):
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    OTHER = "other"


@dataclass
class SecretFinding:
    rule_id: str
    secret_type: SecretType
    file_path: str
    commit: str
    author: str
    date: str
    line: int
    match_redacted: str  # Never store full secret
    repository: str
    is_active: bool = True  # Assume active until verified


@dataclass
class ScanResult:
    findings: list[SecretFinding] = field(default_factory=list)
    summary: str = ""
    active_secrets_count: int = 0
    repositories_scanned: int = 0


@dataclass
class SkillInput:
    repositories: list[str] = field(default_factory=list)
    scan_history: bool = True
    custom_rules: list[str] = field(default_factory=list)


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ScanResult] = None
    error: Optional[str] = None


async def run_gitleaks(repo_url: str, scan_history: bool) -> list[SecretFinding]:
    """Run Gitleaks against a Git repository."""
    # TODO: Invoke Gitleaks container via Docker API
    return []


async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    try:
        all_findings: list[SecretFinding] = []

        for repo in input.repositories:
            findings = await run_gitleaks(repo, input.scan_history)
            all_findings.extend(findings)

        result = ScanResult(
            findings=all_findings,
            active_secrets_count=sum(1 for f in all_findings if f.is_active),
            repositories_scanned=len(input.repositories),
            summary=f"Scan terminé : {len(all_findings)} secrets détectés dans {len(input.repositories)} repos",
        )
        return SkillOutput(success=True, result=result)
    except Exception as e:
        return SkillOutput(success=False, error=str(e))
