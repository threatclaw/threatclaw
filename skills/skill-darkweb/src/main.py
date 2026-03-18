"""
skill-darkweb — Dark web monitoring & breach detection
HaveIBeenPwned API v3 for breach/leak detection

This module provides the business logic for dark web monitoring.
"""

import json
import asyncio
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


# ── Constants ──────────────────────────────────────────────

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_RATE_LIMIT_SECONDS = 1.6  # 10 req/min for free tier
HIBP_TIMEOUT = 15  # seconds per request


# ── Data Models ────────────────────────────────────────────

class BreachCriticality(Enum):
    CRITICAL = "critical"  # passwords + recent
    HIGH = "high"          # passwords + old
    MEDIUM = "medium"      # sensitive data, no passwords
    LOW = "low"            # public data only


SENSITIVE_DATA_CLASSES = {
    "Passwords", "Password hints", "Credit cards",
    "Bank account numbers", "Security questions and answers",
    "Private messages", "Chat logs", "SMS messages",
    "Auth tokens", "Social security numbers",
}

PASSWORD_DATA_CLASSES = {"Passwords", "Password hints"}


@dataclass
class Breach:
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    affected_email: str
    pwn_count: int = 0
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
    criticality: BreachCriticality = BreachCriticality.MEDIUM
    description: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["criticality"] = self.criticality.value
        return d


@dataclass
class PasteEntry:
    source: str
    paste_id: str
    title: str
    date: str
    email: str
    email_count: int = 0


@dataclass
class ScanResult:
    breaches: list[Breach] = field(default_factory=list)
    pastes: list[PasteEntry] = field(default_factory=list)
    exposed_accounts: int = 0
    unique_breaches: int = 0
    domains_checked: int = 0
    emails_checked: int = 0
    critical_count: int = 0
    high_count: int = 0
    recommendations: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["breaches"] = [b.to_dict() for b in self.breaches]
        return d


@dataclass
class SkillInput:
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    check_pastes: bool = True
    include_unverified: bool = False


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ScanResult] = None
    error: Optional[str] = None


# ── Email Anonymization ───────────────────────────────────

def anonymize_email(email: str) -> str:
    """Anonymize email: john.doe@company.com -> j***@company.com"""
    if "@" not in email:
        return "***"
    local, domain = email.rsplit("@", 1)
    if len(local) <= 1:
        return f"*@{domain}"
    return f"{local[0]}***@{domain}"


# ── Criticality Assessment ─────────────────────────────────

def assess_breach_criticality(
    data_classes: list[str],
    breach_date: str,
    is_verified: bool,
) -> BreachCriticality:
    """Assess criticality of a breach based on data exposed."""
    has_passwords = bool(set(data_classes) & PASSWORD_DATA_CLASSES)
    has_sensitive = bool(set(data_classes) & SENSITIVE_DATA_CLASSES)

    # Check recency
    is_recent = False
    try:
        if breach_date:
            dt = datetime.fromisoformat(breach_date)
            age_days = (datetime.now() - dt).days
            is_recent = age_days < 365
    except (ValueError, TypeError):
        pass

    if has_passwords and is_recent:
        return BreachCriticality.CRITICAL
    elif has_passwords:
        return BreachCriticality.HIGH
    elif has_sensitive:
        return BreachCriticality.MEDIUM
    else:
        return BreachCriticality.LOW


# ── HIBP API Calls ─────────────────────────────────────────

async def _hibp_request(
    endpoint: str,
    http_get=None,
) -> Optional[list | dict]:
    """Make an HIBP API request with rate limiting."""
    url = f"{HIBP_API_BASE}{endpoint}"

    try:
        if http_get:
            return await http_get(url)
        else:
            # Fallback to curl (credentials injected by proxy in production)
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-f",
                "-H", "user-agent: ThreatClaw/0.1.0",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=HIBP_TIMEOUT
            )
            if proc.returncode != 0:
                return None
            output = stdout.decode("utf-8", errors="replace").strip()
            if not output:
                return None
            return json.loads(output)
    except Exception:
        return None


async def check_email_breaches(
    email: str,
    include_unverified: bool = False,
    http_get=None,
) -> list[Breach]:
    """Check email against HIBP breached accounts API."""
    truncate = "&truncateResponse=false"
    unverified = "&includeUnverified=true" if include_unverified else ""
    endpoint = f"/breachedaccount/{email}?{truncate}{unverified}"

    data = await _hibp_request(endpoint, http_get)
    if not data or not isinstance(data, list):
        return []

    breaches = []
    for entry in data:
        data_classes = entry.get("DataClasses", [])
        breach_date = entry.get("BreachDate", "")
        is_verified = entry.get("IsVerified", False)

        breaches.append(Breach(
            name=entry.get("Name", "Unknown"),
            title=entry.get("Title", "Unknown"),
            domain=entry.get("Domain", ""),
            breach_date=breach_date,
            added_date=entry.get("AddedDate", ""),
            affected_email=anonymize_email(email),
            pwn_count=entry.get("PwnCount", 0),
            data_classes=data_classes,
            is_verified=is_verified,
            is_sensitive=entry.get("IsSensitive", False),
            criticality=assess_breach_criticality(
                data_classes, breach_date, is_verified
            ),
            description=entry.get("Description", ""),
        ))

    return breaches


async def check_email_pastes(
    email: str,
    http_get=None,
) -> list[PasteEntry]:
    """Check email against HIBP paste sites."""
    endpoint = f"/pasteaccount/{email}"
    data = await _hibp_request(endpoint, http_get)
    if not data or not isinstance(data, list):
        return []

    return [
        PasteEntry(
            source=entry.get("Source", ""),
            paste_id=entry.get("Id", ""),
            title=entry.get("Title", ""),
            date=entry.get("Date", ""),
            email=anonymize_email(email),
            email_count=entry.get("EmailCount", 0),
        )
        for entry in data
    ]


async def check_domain_breaches(
    domain: str,
    http_get=None,
) -> list[Breach]:
    """List breaches affecting a specific domain."""
    endpoint = f"/breaches?domain={domain}"
    data = await _hibp_request(endpoint, http_get)
    if not data or not isinstance(data, list):
        return []

    return [
        Breach(
            name=entry.get("Name", "Unknown"),
            title=entry.get("Title", "Unknown"),
            domain=entry.get("Domain", ""),
            breach_date=entry.get("BreachDate", ""),
            added_date=entry.get("AddedDate", ""),
            affected_email=f"*@{domain}",
            pwn_count=entry.get("PwnCount", 0),
            data_classes=entry.get("DataClasses", []),
            is_verified=entry.get("IsVerified", False),
            criticality=assess_breach_criticality(
                entry.get("DataClasses", []),
                entry.get("BreachDate", ""),
                entry.get("IsVerified", False),
            ),
        )
        for entry in data
    ]


# ── Recommendations ────────────────────────────────────────

def generate_recommendations(breaches: list[Breach]) -> list[str]:
    """Generate actionable recommendations based on findings."""
    recs = []
    has_critical = any(b.criticality == BreachCriticality.CRITICAL for b in breaches)
    has_passwords = any(
        set(b.data_classes) & PASSWORD_DATA_CLASSES for b in breaches
    )

    if has_critical:
        recs.append(
            "CRITIQUE : Réinitialiser immédiatement les mots de passe des comptes "
            "exposés dans des breaches récentes contenant des passwords."
        )
    if has_passwords:
        recs.append(
            "ÉLEVÉ : Activer l'authentification multi-facteur (MFA) sur tous les "
            "comptes dont les credentials ont été exposés."
        )
    if breaches:
        recs.append(
            "MOYEN : Informer les utilisateurs concernés de la compromission "
            "de leurs données conformément à l'Art.23 NIS2."
        )
        recs.append(
            "MOYEN : Vérifier que les mots de passe exposés ne sont pas "
            "réutilisés sur d'autres services (credential stuffing)."
        )
        recs.append(
            "FAIBLE : Mettre en place une surveillance continue des fuites "
            "via des vérifications HIBP automatisées (scheduler ThreatClaw)."
        )

    return recs


# ── Main Entry Point ───────────────────────────────────────

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    if not input.emails and not input.domains:
        return SkillOutput(
            success=False,
            error="Aucun email ou domaine fourni.",
        )

    start_time = datetime.now(timezone.utc)

    try:
        all_breaches: list[Breach] = []
        all_pastes: list[PasteEntry] = []
        exposed_emails = set()

        # Check each email with rate limiting
        for email in input.emails:
            breaches = await check_email_breaches(
                email, input.include_unverified
            )
            all_breaches.extend(breaches)
            if breaches:
                exposed_emails.add(email)

            if input.check_pastes:
                pastes = await check_email_pastes(email)
                all_pastes.extend(pastes)

            # Rate limiting
            await asyncio.sleep(HIBP_RATE_LIMIT_SECONDS)

        # Check domains
        for domain in input.domains:
            breaches = await check_domain_breaches(domain)
            all_breaches.extend(breaches)

        # Sort by criticality
        crit_order = {
            BreachCriticality.CRITICAL: 0,
            BreachCriticality.HIGH: 1,
            BreachCriticality.MEDIUM: 2,
            BreachCriticality.LOW: 3,
        }
        all_breaches.sort(key=lambda b: crit_order.get(b.criticality, 99))

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        critical_count = sum(
            1 for b in all_breaches if b.criticality == BreachCriticality.CRITICAL
        )
        high_count = sum(
            1 for b in all_breaches if b.criticality == BreachCriticality.HIGH
        )

        unique_breach_names = set(b.name for b in all_breaches)

        result = ScanResult(
            breaches=all_breaches,
            pastes=all_pastes,
            exposed_accounts=len(exposed_emails),
            unique_breaches=len(unique_breach_names),
            domains_checked=len(input.domains),
            emails_checked=len(input.emails),
            critical_count=critical_count,
            high_count=high_count,
            recommendations=generate_recommendations(all_breaches),
            scan_duration_seconds=round(duration, 2),
        )

        return SkillOutput(success=True, result=result)

    except Exception as e:
        return SkillOutput(success=False, error=f"Erreur inattendue : {e}")
