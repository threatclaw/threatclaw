"""
skill-email-audit — Email security audit
DMARC/SPF/DKIM verification via DNS queries

This module checks email authentication records for domains
and produces a security maturity score.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


# ── Data Models ────────────────────────────────────────────

class DmarcPolicy(Enum):
    REJECT = "reject"
    QUARANTINE = "quarantine"
    NONE = "none"
    MISSING = "missing"

    @property
    def score_value(self) -> int:
        return {"reject": 40, "quarantine": 25, "none": 5, "missing": 0}[self.value]


class SpfQualifier(Enum):
    FAIL = "-all"        # strict — best
    SOFTFAIL = "~all"    # common — acceptable
    NEUTRAL = "?all"     # weak
    PASS = "+all"        # dangerous — allows all
    MISSING = "missing"

    @property
    def score_value(self) -> int:
        return {
            "-all": 30, "~all": 20, "?all": 5, "+all": 0, "missing": 0
        }[self.value]


@dataclass
class DmarcResult:
    exists: bool = False
    policy: DmarcPolicy = DmarcPolicy.MISSING
    pct: int = 0
    rua: str = ""  # aggregate report URI
    ruf: str = ""  # forensic report URI
    subdomain_policy: str = ""
    raw_record: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class SpfResult:
    exists: bool = False
    qualifier: SpfQualifier = SpfQualifier.MISSING
    include_count: int = 0
    lookup_count: int = 0
    mechanisms: list[str] = field(default_factory=list)
    raw_record: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class DkimResult:
    found: bool = False
    selectors_found: list[str] = field(default_factory=list)
    selectors_tested: list[str] = field(default_factory=list)
    key_sizes: dict[str, int] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)


@dataclass
class DomainAudit:
    domain: str
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    spf: SpfResult = field(default_factory=SpfResult)
    dkim: DkimResult = field(default_factory=DkimResult)
    score: int = 0  # 0-100
    recommendations: list[str] = field(default_factory=list)
    timestamp: str = ""

    def calculate_score(self) -> int:
        """Calculate email security maturity score (0-100)."""
        score = 0
        # DMARC: up to 40 points
        score += self.dmarc.policy.score_value
        if self.dmarc.rua:
            score += 5  # reporting configured
        if self.dmarc.pct == 100:
            score += 5  # full enforcement

        # SPF: up to 30 points
        score += self.spf.qualifier.score_value

        # DKIM: up to 30 points
        if self.dkim.found:
            score += 15
            # Bonus for strong keys
            for size in self.dkim.key_sizes.values():
                if size >= 2048:
                    score += 5
                    break
            if len(self.dkim.selectors_found) > 0:
                score += 10

        self.score = min(score, 100)
        return self.score

    def generate_recommendations(self) -> list[str]:
        """Generate prioritized recommendations."""
        recs = []
        # DMARC
        if self.dmarc.policy == DmarcPolicy.MISSING:
            recs.append(
                "CRITIQUE : Ajouter un enregistrement DMARC. "
                "Commencer par v=DMARC1; p=none; rua=mailto:dmarc@votre-domaine.com"
            )
        elif self.dmarc.policy == DmarcPolicy.NONE:
            recs.append(
                "ÉLEVÉ : Passer la politique DMARC de 'none' à 'quarantine' puis 'reject'. "
                "Analyser les rapports RUA avant de durcir."
            )
        elif self.dmarc.policy == DmarcPolicy.QUARANTINE:
            recs.append(
                "MOYEN : Envisager de passer DMARC à 'reject' pour une protection maximale."
            )
        if self.dmarc.exists and not self.dmarc.rua:
            recs.append(
                "MOYEN : Configurer une adresse RUA pour recevoir les rapports DMARC agrégés."
            )
        if self.dmarc.exists and self.dmarc.pct < 100:
            recs.append(
                f"MOYEN : Augmenter le pourcentage DMARC de {self.dmarc.pct}% à 100%."
            )

        # SPF
        if self.spf.qualifier == SpfQualifier.MISSING:
            recs.append(
                "CRITIQUE : Ajouter un enregistrement SPF. "
                "Exemple : v=spf1 include:_spf.google.com -all"
            )
        elif self.spf.qualifier == SpfQualifier.PASS:
            recs.append(
                "CRITIQUE : L'enregistrement SPF utilise '+all' — tout le monde peut envoyer "
                "des emails au nom de votre domaine. Changer immédiatement pour '-all' ou '~all'."
            )
        elif self.spf.qualifier == SpfQualifier.NEUTRAL:
            recs.append(
                "ÉLEVÉ : L'enregistrement SPF utilise '?all' (neutre). "
                "Renforcer avec '~all' ou '-all'."
            )
        if self.spf.lookup_count > 10:
            recs.append(
                f"ÉLEVÉ : SPF dépasse la limite de 10 lookups DNS ({self.spf.lookup_count}). "
                "Aplatir les includes ou utiliser des IP directement."
            )

        # DKIM
        if not self.dkim.found:
            recs.append(
                "ÉLEVÉ : Aucun sélecteur DKIM détecté. Configurer DKIM pour signer les emails sortants."
            )
        for selector, size in self.dkim.key_sizes.items():
            if size < 2048:
                recs.append(
                    f"MOYEN : La clé DKIM '{selector}' fait {size} bits. "
                    "Passer à 2048 bits minimum."
                )

        self.recommendations = recs
        return recs


# ── DNS Queries ────────────────────────────────────────────

async def _dns_query(domain: str, record_type: str = "TXT") -> list[str]:
    """Query DNS records using dig."""
    cmd = ["dig", "+short", record_type, domain]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode("utf-8", errors="replace").strip()
        if not output:
            return []
        # dig returns quoted strings, remove quotes
        lines = []
        for line in output.split("\n"):
            line = line.strip().strip('"')
            if line:
                lines.append(line)
        return lines
    except (asyncio.TimeoutError, FileNotFoundError):
        return []


# ── DMARC Check ───────────────────────────────────────────

async def check_dmarc(domain: str) -> DmarcResult:
    """Check DMARC record for a domain."""
    result = DmarcResult()
    records = await _dns_query(f"_dmarc.{domain}")

    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc_records:
        result.issues.append("Aucun enregistrement DMARC trouvé")
        return result

    result.exists = True
    record = dmarc_records[0]
    result.raw_record = record

    # Parse policy
    policy_match = re.search(r"p=(none|quarantine|reject)", record, re.IGNORECASE)
    if policy_match:
        result.policy = DmarcPolicy(policy_match.group(1).lower())

    # Parse pct
    pct_match = re.search(r"pct=(\d+)", record)
    result.pct = int(pct_match.group(1)) if pct_match else 100

    # Parse rua
    rua_match = re.search(r"rua=([^;]+)", record)
    if rua_match:
        result.rua = rua_match.group(1).strip()

    # Parse ruf
    ruf_match = re.search(r"ruf=([^;]+)", record)
    if ruf_match:
        result.ruf = ruf_match.group(1).strip()

    # Parse subdomain policy
    sp_match = re.search(r"sp=(none|quarantine|reject)", record, re.IGNORECASE)
    if sp_match:
        result.subdomain_policy = sp_match.group(1)

    # Issues
    if result.policy == DmarcPolicy.NONE:
        result.issues.append("Politique DMARC en mode 'none' — pas de protection active")
    if result.pct < 100:
        result.issues.append(f"DMARC appliqué à seulement {result.pct}% des messages")
    if not result.rua:
        result.issues.append("Pas d'adresse de reporting RUA configurée")

    return result


# ── SPF Check ─────────────────────────────────────────────

async def check_spf(domain: str) -> SpfResult:
    """Check SPF record for a domain."""
    result = SpfResult()
    records = await _dns_query(domain)

    spf_records = [r for r in records if "v=spf1" in r]
    if not spf_records:
        result.issues.append("Aucun enregistrement SPF trouvé")
        return result

    result.exists = True
    record = spf_records[0]
    result.raw_record = record

    # Parse mechanisms
    parts = record.split()
    result.mechanisms = [p for p in parts if p != "v=spf1"]

    # Count includes
    result.include_count = sum(1 for p in parts if p.startswith("include:"))

    # Estimate DNS lookups (includes + a + mx + redirect)
    lookup_keywords = ["include:", "a:", "mx:", "redirect=", "a ", "mx "]
    result.lookup_count = sum(
        1 for p in parts
        if any(p.startswith(kw) or p == kw.strip() for kw in lookup_keywords)
    )

    # Determine qualifier
    if "+all" in record:
        result.qualifier = SpfQualifier.PASS
        result.issues.append("DANGER : '+all' autorise n'importe qui à envoyer des emails")
    elif "?all" in record:
        result.qualifier = SpfQualifier.NEUTRAL
        result.issues.append("'?all' ne protège pas contre le spoofing")
    elif "~all" in record:
        result.qualifier = SpfQualifier.SOFTFAIL
    elif "-all" in record:
        result.qualifier = SpfQualifier.FAIL

    if result.lookup_count > 10:
        result.issues.append(
            f"Dépasse la limite de 10 lookups DNS ({result.lookup_count})"
        )

    return result


# ── DKIM Check ────────────────────────────────────────────

DEFAULT_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "dkim", "mail", "k1", "s1", "s2", "protonmail",
    "protonmail2", "protonmail3", "mxvault",
]


async def check_dkim(
    domain: str, selectors: list[str] | None = None
) -> DkimResult:
    """Check DKIM selectors for a domain."""
    result = DkimResult()
    selectors = selectors or DEFAULT_DKIM_SELECTORS
    result.selectors_tested = selectors

    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = await _dns_query(dkim_domain)

        dkim_records = [r for r in records if "v=DKIM1" in r or "p=" in r]
        if dkim_records:
            result.found = True
            result.selectors_found.append(selector)

            # Try to determine key size from the public key
            for rec in dkim_records:
                p_match = re.search(r"p=([A-Za-z0-9+/=]+)", rec)
                if p_match:
                    key_b64 = p_match.group(1)
                    # Approximate key size from base64 length
                    key_bytes = len(key_b64) * 3 // 4
                    key_bits = key_bytes * 8
                    result.key_sizes[selector] = key_bits

    if not result.found:
        result.issues.append("Aucun sélecteur DKIM valide trouvé")

    for selector, size in result.key_sizes.items():
        if size < 2048:
            result.issues.append(
                f"Clé DKIM '{selector}' trop courte ({size} bits, minimum 2048 recommandé)"
            )

    return result


# ── Main Entry Point ───────────────────────────────────────

@dataclass
class SkillInput:
    domains: list[str] = field(default_factory=list)
    dkim_selectors: list[str] | None = None


@dataclass
class SkillOutput:
    success: bool = False
    audits: list[DomainAudit] = field(default_factory=list)
    overall_score: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "audits": [asdict(a) for a in self.audits],
            "overall_score": self.overall_score,
            "error": self.error,
        }


async def audit_domain(
    domain: str, dkim_selectors: list[str] | None = None
) -> DomainAudit:
    """Run full email security audit for a domain."""
    audit = DomainAudit(
        domain=domain,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # Run checks in parallel
    dmarc_task = check_dmarc(domain)
    spf_task = check_spf(domain)
    dkim_task = check_dkim(domain, dkim_selectors)

    audit.dmarc, audit.spf, audit.dkim = await asyncio.gather(
        dmarc_task, spf_task, dkim_task
    )

    audit.calculate_score()
    audit.generate_recommendations()

    return audit


async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    if not input.domains:
        return SkillOutput(
            success=False,
            error="Aucun domaine fourni. Spécifiez des noms de domaine à auditer.",
        )

    try:
        audits = []
        for domain in input.domains:
            audit = await audit_domain(domain, input.dkim_selectors)
            audits.append(audit)

        overall = sum(a.score for a in audits) // max(len(audits), 1)

        return SkillOutput(
            success=True,
            audits=audits,
            overall_score=overall,
        )
    except Exception as e:
        return SkillOutput(success=False, error=f"Erreur inattendue : {e}")
