"""
skill-secrets — Secret & credential detection
Gitleaks for Git repository scanning + classification

This module provides the business logic for secret detection.
"""

import json
import asyncio
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone, timedelta


# ── Constants ──────────────────────────────────────────────

GITLEAKS_TIMEOUT = 600  # 10 minutes for large repos
REDACT_LENGTH = 8  # characters to show before redaction


# ── Data Models ────────────────────────────────────────────

class SecretType(Enum):
    AWS_KEY = "aws_key"
    GCP_KEY = "gcp_key"
    AZURE_KEY = "azure_key"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    SLACK_TOKEN = "slack_token"
    API_KEY = "api_key"
    PASSWORD = "password"
    JWT_TOKEN = "jwt_token"
    OAUTH_TOKEN = "oauth_token"
    PRIVATE_KEY = "private_key"
    SSH_KEY = "ssh_key"
    CONNECTION_STRING = "connection_string"
    GENERIC_SECRET = "generic_secret"
    OTHER = "other"

    @classmethod
    def from_rule_id(cls, rule_id: str) -> "SecretType":
        """Map Gitleaks rule IDs to SecretType."""
        rule_lower = rule_id.lower()
        mapping = {
            "aws": cls.AWS_KEY,
            "gcp": cls.GCP_KEY,
            "azure": cls.AZURE_KEY,
            "github": cls.GITHUB_TOKEN,
            "gitlab": cls.GITLAB_TOKEN,
            "slack": cls.SLACK_TOKEN,
            "jwt": cls.JWT_TOKEN,
            "oauth": cls.OAUTH_TOKEN,
            "private-key": cls.PRIVATE_KEY,
            "ssh": cls.SSH_KEY,
            "password": cls.PASSWORD,
            "passwd": cls.PASSWORD,
            "connection": cls.CONNECTION_STRING,
            "database": cls.CONNECTION_STRING,
            "generic": cls.GENERIC_SECRET,
        }
        # Check API key before generic (more specific first)
        if "api" in rule_lower and "key" in rule_lower:
            return cls.API_KEY
        for key, val in mapping.items():
            if key in rule_lower:
                return val
        return cls.OTHER


class Criticality(Enum):
    CRITICAL = "critical"  # Active secret, recent commit
    HIGH = "high"          # Recent commit (< 90 days)
    MEDIUM = "medium"      # Old but potentially valid
    LOW = "low"            # In test/example files


@dataclass
class SecretFinding:
    rule_id: str
    secret_type: SecretType
    file_path: str
    commit: str
    author: str
    date: str
    line: int
    match_redacted: str  # NEVER store full secret
    repository: str
    criticality: Criticality = Criticality.MEDIUM
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["secret_type"] = self.secret_type.value
        d["criticality"] = self.criticality.value
        return d


@dataclass
class ScanResult:
    findings: list[SecretFinding] = field(default_factory=list)
    summary: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    repositories_scanned: int = 0
    commits_analyzed: int = 0
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class SkillInput:
    repositories: list[str] = field(default_factory=list)
    scan_history: bool = True
    include_tests: bool = False  # include test/example files


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ScanResult] = None
    error: Optional[str] = None


# ── Redaction ──────────────────────────────────────────────

def redact_secret(secret: str) -> str:
    """Redact a secret value, showing only first few chars."""
    if len(secret) <= REDACT_LENGTH:
        return "*" * len(secret)
    return secret[:REDACT_LENGTH] + "*" * (len(secret) - REDACT_LENGTH)


# ── Criticality Assessment ─────────────────────────────────

TEST_PATH_PATTERNS = [
    r"test[s]?/",
    r"spec[s]?/",
    r"__test__",
    r"\.test\.",
    r"\.spec\.",
    r"example",
    r"sample",
    r"mock",
    r"fixture",
    r"\.env\.example",
    r"\.env\.sample",
    r"\.env\.template",
]


def assess_criticality(
    file_path: str,
    commit_date: str,
    rule_id: str,
) -> Criticality:
    """Assess the criticality of a detected secret."""
    # Check if it's in a test/example file
    for pattern in TEST_PATH_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return Criticality.LOW

    # Check commit age
    is_recent = False
    is_somewhat_recent = False
    try:
        if commit_date:
            dt = datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - dt
            if age < timedelta(days=30):
                is_recent = True
            elif age < timedelta(days=90):
                is_somewhat_recent = True
    except (ValueError, TypeError):
        pass

    # Private keys and AWS keys are always at least HIGH
    is_high_risk_type = any(
        kw in rule_id.lower() for kw in ["private-key", "ssh", "aws"]
    )

    if is_recent:
        return Criticality.CRITICAL
    elif is_somewhat_recent:
        return Criticality.HIGH
    elif is_high_risk_type:
        return Criticality.HIGH

    return Criticality.MEDIUM


# ── Gitleaks Integration ───────────────────────────────────

def _parse_gitleaks_output(output: str, repository: str) -> list[SecretFinding]:
    """Parse Gitleaks JSON output into SecretFindings."""
    findings: list[SecretFinding] = []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, list):
        return findings

    for entry in data:
        rule_id = entry.get("RuleID", "unknown")
        secret = entry.get("Secret", "")
        file_path = entry.get("File", "")
        commit = entry.get("Commit", "")
        author = entry.get("Author", "")
        date = entry.get("Date", "")
        line = entry.get("StartLine", 0)
        description = entry.get("Description", "")
        tags = entry.get("Tags", [])

        finding = SecretFinding(
            rule_id=rule_id,
            secret_type=SecretType.from_rule_id(rule_id),
            file_path=file_path,
            commit=commit[:12] if commit else "",
            author=author,
            date=date,
            line=line,
            match_redacted=redact_secret(secret),
            repository=repository,
            criticality=assess_criticality(file_path, date, rule_id),
            description=description,
            tags=tags if isinstance(tags, list) else [],
        )
        findings.append(finding)

    return findings


async def run_gitleaks(
    repo_path: str,
    repository: str,
    scan_history: bool = True,
) -> list[SecretFinding]:
    """Run Gitleaks against a Git repository."""
    cmd = [
        "docker", "exec", "gitleaks",
        "gitleaks", "detect",
        "--source", repo_path,
        "-f", "json",
        "--no-banner",
        "--exit-code", "0",  # don't fail on findings
    ]

    if not scan_history:
        cmd.append("--no-git")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=GITLEAKS_TIMEOUT
        )

        output = stdout.decode("utf-8", errors="replace")
        return _parse_gitleaks_output(output, repository)

    except asyncio.TimeoutError:
        return [
            SecretFinding(
                rule_id="SCAN-TIMEOUT",
                secret_type=SecretType.OTHER,
                file_path="",
                commit="",
                author="",
                date="",
                line=0,
                match_redacted="",
                repository=repository,
                criticality=Criticality.MEDIUM,
                description=f"Scan exceeded {GITLEAKS_TIMEOUT}s timeout",
            )
        ]
    except FileNotFoundError:
        raise RuntimeError("Docker not found. Ensure Gitleaks container is running.")


async def clone_repo(repo_url: str, dest: str) -> bool:
    """Clone a Git repository to a temporary location."""
    cmd = ["git", "clone", "--quiet", repo_url, dest]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=300)
        return proc.returncode == 0
    except (asyncio.TimeoutError, FileNotFoundError):
        return False


# ── Main Entry Point ───────────────────────────────────────

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    if not input.repositories:
        return SkillOutput(
            success=False,
            error="Aucun dépôt fourni. Spécifiez des URLs de repositories Git.",
        )

    start_time = datetime.now(timezone.utc)

    try:
        all_findings: list[SecretFinding] = []

        for repo in input.repositories:
            # For local paths, scan directly
            # For URLs, clone first then scan
            repo_path = repo
            if repo.startswith(("http://", "https://", "git@")):
                import tempfile
                tmpdir = tempfile.mkdtemp(prefix="threatclaw-secrets-")
                success = await clone_repo(repo, tmpdir)
                if not success:
                    return SkillOutput(
                        success=False,
                        error=f"Impossible de cloner {repo}",
                    )
                repo_path = tmpdir

            findings = await run_gitleaks(
                repo_path, repo, input.scan_history
            )

            if not input.include_tests:
                findings = [
                    f for f in findings
                    if f.criticality != Criticality.LOW
                ]

            all_findings.extend(findings)

        # Sort by criticality
        crit_order = {
            Criticality.CRITICAL: 0,
            Criticality.HIGH: 1,
            Criticality.MEDIUM: 2,
            Criticality.LOW: 3,
        }
        all_findings.sort(key=lambda f: crit_order.get(f.criticality, 99))

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        counts = {c: 0 for c in Criticality}
        for f in all_findings:
            counts[f.criticality] += 1

        result = ScanResult(
            findings=all_findings,
            critical_count=counts[Criticality.CRITICAL],
            high_count=counts[Criticality.HIGH],
            medium_count=counts[Criticality.MEDIUM],
            low_count=counts[Criticality.LOW],
            repositories_scanned=len(input.repositories),
            scan_duration_seconds=round(duration, 2),
            summary=(
                f"Scan terminé en {duration:.0f}s — "
                f"{len(all_findings)} secrets détectés dans "
                f"{len(input.repositories)} repos "
                f"({counts[Criticality.CRITICAL]} critiques, "
                f"{counts[Criticality.HIGH]} élevés)"
            ),
        )

        return SkillOutput(success=True, result=result)

    except Exception as e:
        return SkillOutput(success=False, error=f"Erreur inattendue : {e}")
