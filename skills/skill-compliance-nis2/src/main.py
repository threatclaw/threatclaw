"""
skill-compliance-nis2 -- NIS2 compliance mapping & scoring
Maps security findings to NIS2 Directive (EU) 2022/2555 Art.21 sections,
computes compliance scores, performs gap analysis, and generates action plans.

This module provides the full business logic for NIS2 Art.21 compliance
assessment across all 10 mandatory security-measure categories.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingSource(Enum):
    VULN_SCAN = "vuln_scan"
    SECRETS = "secrets"
    EMAIL_AUDIT = "email_audit"
    DARKWEB = "darkweb"
    PHISHING = "phishing"
    SOC_MONITOR = "soc_monitor"
    CLOUD_POSTURE = "cloud_posture"

    @classmethod
    def from_string(cls, s: str) -> "FindingSource":
        mapping = {
            "vuln_scan": cls.VULN_SCAN,
            "secrets": cls.SECRETS,
            "email_audit": cls.EMAIL_AUDIT,
            "darkweb": cls.DARKWEB,
            "phishing": cls.PHISHING,
            "soc_monitor": cls.SOC_MONITOR,
            "cloud_posture": cls.CLOUD_POSTURE,
        }
        return mapping.get(s.lower(), cls.VULN_SCAN)


class Priority(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MaturityLevel(Enum):
    INITIAL = 1
    GERE = 2
    DEFINI = 3
    MESURE = 4
    OPTIMISE = 5

    @property
    def label_fr(self) -> str:
        labels = {
            1: "Initial",
            2: "G\u00e9r\u00e9",
            3: "D\u00e9fini",
            4: "Mesur\u00e9",
            5: "Optimis\u00e9",
        }
        return labels[self.value]


# ---------------------------------------------------------------------------
# NIS2 Article 21 data model
# ---------------------------------------------------------------------------

@dataclass
class NIS2Article:
    id: str
    title_fr: str
    description_fr: str
    required_controls: list[str] = field(default_factory=list)
    mapping_keywords: list[str] = field(default_factory=list)
    related_skills: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# NIS2 Article 21 -- Complete mapping of all 10 sections
# ---------------------------------------------------------------------------

NIS2_ARTICLES: dict[str, NIS2Article] = {
    "art21_2a": NIS2Article(
        id="art21_2a",
        title_fr="Analyse des risques et s\u00e9curit\u00e9 des SI",
        description_fr=(
            "Politiques relatives \u00e0 l'analyse des risques et \u00e0 la "
            "s\u00e9curit\u00e9 des syst\u00e8mes d'information, y compris "
            "l'\u00e9valuation et le traitement des risques."
        ),
        required_controls=[
            "politique de s\u00e9curit\u00e9",
            "analyse de risques",
            "inventaire des actifs",
            "classification des actifs",
            "traitement des risques",
            "registre des risques",
        ],
        mapping_keywords=[
            "risque", "risk", "politique", "policy", "actif", "asset",
            "vuln\u00e9rabilit\u00e9", "vulnerability", "cve", "cvss",
            "inventaire", "inventory", "classification", "posture",
            "security policy", "s\u00e9curit\u00e9", "scan",
        ],
        related_skills=["skill-vuln-scan", "skill-cloud-posture"],
    ),
    "art21_2b": NIS2Article(
        id="art21_2b",
        title_fr="Gestion des incidents",
        description_fr=(
            "Gestion des incidents de s\u00e9curit\u00e9, y compris les "
            "proc\u00e9dures et outils de d\u00e9tection, d'analyse, de "
            "confinement et de r\u00e9ponse aux incidents."
        ),
        required_controls=[
            "proc\u00e9dure de gestion des incidents",
            "d\u00e9tection des incidents",
            "classification des incidents",
            "notification des incidents",
            "analyse post-incident",
            "plan de r\u00e9ponse aux incidents",
        ],
        mapping_keywords=[
            "incident", "alerte", "alert", "sigma", "soc", "d\u00e9tection",
            "detection", "triage", "r\u00e9ponse", "response", "siem",
            "corr\u00e9lation", "correlation", "log", "monitoring",
            "surveillance", "intrusion",
        ],
        related_skills=["skill-soc-monitor"],
    ),
    "art21_2c": NIS2Article(
        id="art21_2c",
        title_fr="Continuit\u00e9 des activit\u00e9s et gestion de crise",
        description_fr=(
            "Continuit\u00e9 des activit\u00e9s, gestion de crise, y compris "
            "la gestion des sauvegardes, la reprise apr\u00e8s sinistre et la "
            "gestion de crise."
        ),
        required_controls=[
            "plan de continuit\u00e9 d'activit\u00e9",
            "plan de reprise d'activit\u00e9",
            "sauvegardes",
            "tests de restauration",
            "gestion de crise",
            "communication de crise",
        ],
        mapping_keywords=[
            "continuit\u00e9", "continuity", "sauvegarde", "backup",
            "restauration", "restore", "reprise", "recovery", "disaster",
            "crise", "crisis", "pca", "pra", "rpo", "rto", "r\u00e9silience",
            "resilience", "disponibilit\u00e9", "availability",
        ],
        related_skills=["skill-cloud-posture"],
    ),
    "art21_2d": NIS2Article(
        id="art21_2d",
        title_fr="S\u00e9curit\u00e9 de la cha\u00eene d'approvisionnement",
        description_fr=(
            "S\u00e9curit\u00e9 de la cha\u00eene d'approvisionnement, y "
            "compris les aspects li\u00e9s \u00e0 la s\u00e9curit\u00e9 "
            "concernant les relations entre chaque entit\u00e9 et ses "
            "fournisseurs ou prestataires de services directs."
        ),
        required_controls=[
            "\u00e9valuation des fournisseurs",
            "clauses de s\u00e9curit\u00e9 contractuelles",
            "audit des fournisseurs",
            "gestion des d\u00e9pendances",
            "suivi des vuln\u00e9rabilit\u00e9s tierces",
        ],
        mapping_keywords=[
            "fournisseur", "supplier", "supply chain", "approvisionnement",
            "d\u00e9pendance", "dependency", "tiers", "third-party",
            "sous-traitant", "vendor", "sbom", "librairie", "library",
            "package", "composant", "component", "open source",
        ],
        related_skills=["skill-vuln-scan", "skill-appsec"],
    ),
    "art21_2e": NIS2Article(
        id="art21_2e",
        title_fr="S\u00e9curit\u00e9 dans l'acquisition, d\u00e9veloppement et maintenance des SI",
        description_fr=(
            "S\u00e9curit\u00e9 dans l'acquisition, le d\u00e9veloppement et "
            "la maintenance des r\u00e9seaux et des syst\u00e8mes "
            "d'information, y compris le traitement et la divulgation des "
            "vuln\u00e9rabilit\u00e9s."
        ),
        required_controls=[
            "d\u00e9veloppement s\u00e9curis\u00e9",
            "revue de code",
            "tests de s\u00e9curit\u00e9",
            "gestion des vuln\u00e9rabilit\u00e9s",
            "patch management",
            "configuration s\u00e9curis\u00e9e",
        ],
        mapping_keywords=[
            "d\u00e9veloppement", "development", "code", "application",
            "patch", "mise \u00e0 jour", "update", "configuration",
            "hardening", "durcissement", "sast", "dast", "pentest",
            "test de s\u00e9curit\u00e9", "security test", "cve",
            "vuln\u00e9rabilit\u00e9", "vulnerability", "remediation",
        ],
        related_skills=["skill-vuln-scan", "skill-appsec"],
    ),
    "art21_2f": NIS2Article(
        id="art21_2f",
        title_fr="\u00c9valuation de l'efficacit\u00e9 des mesures",
        description_fr=(
            "Politiques et proc\u00e9dures visant \u00e0 \u00e9valuer "
            "l'efficacit\u00e9 des mesures de gestion des risques en mati\u00e8re "
            "de cybers\u00e9curit\u00e9."
        ),
        required_controls=[
            "indicateurs de performance",
            "audits r\u00e9guliers",
            "tests d'intrusion",
            "revue de direction",
            "am\u00e9lioration continue",
            "tableaux de bord",
        ],
        mapping_keywords=[
            "audit", "efficacit\u00e9", "effectiveness", "kpi", "indicateur",
            "metric", "m\u00e9trique", "benchmark", "conformit\u00e9",
            "compliance", "revue", "review", "am\u00e9lioration",
            "improvement", "tableau de bord", "dashboard", "mesure",
        ],
        related_skills=["skill-report-gen"],
    ),
    "art21_2g": NIS2Article(
        id="art21_2g",
        title_fr="Cyberhygi\u00e8ne et formation",
        description_fr=(
            "Pratiques de base en mati\u00e8re de cyberhygi\u00e8ne et "
            "formation \u00e0 la cybers\u00e9curit\u00e9."
        ),
        required_controls=[
            "programme de sensibilisation",
            "formation cybers\u00e9curit\u00e9",
            "politique de mots de passe",
            "hygi\u00e8ne num\u00e9rique",
            "exercices de phishing",
        ],
        mapping_keywords=[
            "phishing", "hame\u00e7onnage", "sensibilisation", "awareness",
            "formation", "training", "mot de passe", "password",
            "hygi\u00e8ne", "hygiene", "social engineering",
            "ing\u00e9nierie sociale", "email", "courriel",
        ],
        related_skills=["skill-phishing", "skill-email-audit"],
    ),
    "art21_2h": NIS2Article(
        id="art21_2h",
        title_fr="Cryptographie et chiffrement",
        description_fr=(
            "Politiques et proc\u00e9dures relatives \u00e0 l'utilisation de "
            "la cryptographie et, le cas \u00e9ch\u00e9ant, du chiffrement."
        ),
        required_controls=[
            "politique de chiffrement",
            "gestion des cl\u00e9s",
            "chiffrement des donn\u00e9es au repos",
            "chiffrement des donn\u00e9es en transit",
            "certificats et PKI",
        ],
        mapping_keywords=[
            "chiffrement", "encryption", "cryptographie", "cryptography",
            "certificat", "certificate", "ssl", "tls", "https", "pki",
            "cl\u00e9", "key", "secret", "hash", "signature",
            "kms", "hsm",
        ],
        related_skills=["skill-secrets", "skill-cloud-posture"],
    ),
    "art21_2i": NIS2Article(
        id="art21_2i",
        title_fr="Ressources humaines et contr\u00f4le d'acc\u00e8s",
        description_fr=(
            "S\u00e9curit\u00e9 des ressources humaines, politiques de "
            "contr\u00f4le d'acc\u00e8s et gestion des actifs."
        ),
        required_controls=[
            "politique de contr\u00f4le d'acc\u00e8s",
            "gestion des identit\u00e9s",
            "revue des acc\u00e8s",
            "principe du moindre privil\u00e8ge",
            "gestion des d\u00e9parts",
            "s\u00e9curit\u00e9 RH",
        ],
        mapping_keywords=[
            "acc\u00e8s", "access", "identit\u00e9", "identity", "iam",
            "privil\u00e8ge", "privilege", "rbac", "role", "r\u00f4le",
            "utilisateur", "user", "compte", "account", "autorisation",
            "authorization", "permission", "darkweb", "credential",
            "fuite", "leak", "compromis", "exposed",
        ],
        related_skills=["skill-darkweb", "skill-cloud-posture"],
    ),
    "art21_2j": NIS2Article(
        id="art21_2j",
        title_fr="Authentification multi-facteur",
        description_fr=(
            "Utilisation de solutions d'authentification \u00e0 plusieurs "
            "facteurs ou d'authentification continue, de communications "
            "vocales, vid\u00e9o et textuelles s\u00e9curis\u00e9es et de "
            "syst\u00e8mes de communication d'urgence s\u00e9curis\u00e9s."
        ),
        required_controls=[
            "authentification multi-facteur",
            "politique MFA",
            "communications s\u00e9curis\u00e9es",
            "syst\u00e8me de communication d'urgence",
        ],
        mapping_keywords=[
            "mfa", "multi-facteur", "multi-factor", "2fa",
            "authentification", "authentication", "otp", "totp", "fido",
            "sso", "single sign-on", "biom\u00e9trique", "biometric",
            "zero trust",
        ],
        related_skills=["skill-cloud-posture"],
    ),
}


# ---------------------------------------------------------------------------
# Source-to-article mapping (which finding sources relate to which articles)
# ---------------------------------------------------------------------------

SOURCE_TO_ARTICLES: dict[FindingSource, list[str]] = {
    FindingSource.VULN_SCAN: ["art21_2a", "art21_2e"],
    FindingSource.SECRETS: ["art21_2h", "art21_2i"],
    FindingSource.EMAIL_AUDIT: ["art21_2g", "art21_2j"],
    FindingSource.DARKWEB: ["art21_2i"],
    FindingSource.PHISHING: ["art21_2g"],
    FindingSource.SOC_MONITOR: ["art21_2b"],
    FindingSource.CLOUD_POSTURE: ["art21_2a", "art21_2c", "art21_2h", "art21_2i"],
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SecurityFinding:
    source: FindingSource
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    remediation: str = ""
    date: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        return d


@dataclass
class ArticleScore:
    article_id: str
    title: str
    score: int  # 0-100
    maturity_level: int  # 1-5
    findings_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GapItem:
    article_id: str
    article_title: str
    gap_description: str
    priority: Priority
    recommended_action: str
    estimated_effort: str  # "court", "moyen", "long" terme

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["priority"] = self.priority.value
        return d


@dataclass
class ActionItem:
    priority: Priority
    article_id: str
    action_fr: str
    responsible: str  # "RSSI", "DSI", "DG", "IT"
    deadline_category: str  # "imm\u00e9diat", "court_terme", "moyen_terme"
    estimated_cost: str  # "faible", "moyen", "\u00e9lev\u00e9"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["priority"] = self.priority.value
        return d


@dataclass
class ComplianceReport:
    overall_score: int = 0
    article_scores: list[ArticleScore] = field(default_factory=list)
    gaps: list[GapItem] = field(default_factory=list)
    action_plan: list[ActionItem] = field(default_factory=list)
    total_findings: int = 0
    covered_articles: int = 0
    uncovered_articles: int = 0
    maturity_level: int = 1
    summary_fr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "article_scores": [a.to_dict() for a in self.article_scores],
            "gaps": [g.to_dict() for g in self.gaps],
            "action_plan": [a.to_dict() for a in self.action_plan],
            "total_findings": self.total_findings,
            "covered_articles": self.covered_articles,
            "uncovered_articles": self.uncovered_articles,
            "maturity_level": self.maturity_level,
            "summary_fr": self.summary_fr,
        }


@dataclass
class SkillInput:
    findings_source: str = "all"
    period: str = "last_30d"
    include_recommendations: bool = True


@dataclass
class SkillOutput:
    success: bool = False
    report: Optional[ComplianceReport] = None
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "report": self.report.to_dict() if self.report else None,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Severity weights used in scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.1,
}


# ---------------------------------------------------------------------------
# Finding-to-article mapping engine
# ---------------------------------------------------------------------------

def map_finding_to_articles(finding: SecurityFinding) -> list[str]:
    """Return article IDs that a finding relates to.

    Uses two strategies:
    1. Source-based mapping (FindingSource -> default articles)
    2. Keyword matching (finding title+description vs article mapping_keywords)

    Results are deduplicated and returned as a sorted list.
    """
    matched_articles: set[str] = set()

    # Strategy 1: source-based mapping
    source_articles = SOURCE_TO_ARTICLES.get(finding.source, [])
    matched_articles.update(source_articles)

    # Strategy 2: keyword matching on title + description
    text = (finding.title + " " + finding.description).lower()

    for article_id, article in NIS2_ARTICLES.items():
        for keyword in article.mapping_keywords:
            if keyword.lower() in text:
                matched_articles.add(article_id)
                break  # one keyword match is enough for this article

    return sorted(matched_articles)


# ---------------------------------------------------------------------------
# Compliance scoring
# ---------------------------------------------------------------------------

def _score_to_maturity(score: int) -> int:
    """Convert a 0-100 score to a 1-5 maturity level."""
    if score >= 80:
        return 5  # Optimis\u00e9
    if score >= 60:
        return 4  # Mesur\u00e9
    if score >= 40:
        return 3  # D\u00e9fini
    if score >= 20:
        return 2  # G\u00e9r\u00e9
    return 1  # Initial


def calculate_article_score(
    article: NIS2Article,
    findings: list[SecurityFinding],
    controls_met: list[str],
) -> ArticleScore:
    """Calculate compliance score for a single NIS2 article.

    Score is based on:
    - controls_met / required_controls ratio (base score)
    - Weighted downward by finding severity (more critical findings = lower score)

    Articles with no findings and no controls met get score 0 (gap).
    """
    required = article.required_controls
    total_required = len(required)

    if total_required == 0:
        # Article with no defined controls -- full score if any evidence
        base_score = 100 if (findings or controls_met) else 0
    else:
        met_count = sum(1 for c in controls_met if c in required)
        base_score = int((met_count / total_required) * 100)

    # Severity penalty: critical/high findings reduce score
    severity_penalty = 0.0
    fail_count = 0
    pass_count = 0
    for f in findings:
        weight = _SEVERITY_WEIGHTS.get(f.severity.lower(), 0.1)
        if weight >= 0.5:  # medium+ counts as a fail
            severity_penalty += weight * 5  # each critical finding: -5 pts
            fail_count += 1
        else:
            pass_count += 1

    score = max(0, min(100, int(base_score - severity_penalty)))

    # No findings and no controls = definite gap
    if not findings and not controls_met:
        score = 0

    maturity = _score_to_maturity(score)

    # Build gaps list
    gaps: list[str] = []
    if total_required > 0:
        for ctrl in required:
            if ctrl not in controls_met:
                gaps.append(f"Contr\u00f4le manquant : {ctrl}")

    # Build recommendations
    recommendations: list[str] = []
    if score < 50:
        recommendations.append(
            f"Am\u00e9liorer la couverture de l'article {article.id} "
            f"({article.title_fr})"
        )
    if fail_count > 0:
        recommendations.append(
            f"Rem\u00e9dier aux {fail_count} finding(s) de s\u00e9v\u00e9rit\u00e9 "
            f"moyenne ou sup\u00e9rieure"
        )
    if gaps:
        recommendations.append(
            f"Mettre en place les {len(gaps)} contr\u00f4le(s) manquant(s)"
        )

    # Build evidence from controls met
    evidence = [f"Contr\u00f4le en place : {c}" for c in controls_met if c in required]

    return ArticleScore(
        article_id=article.id,
        title=article.title_fr,
        score=score,
        maturity_level=maturity,
        findings_count=len(findings),
        pass_count=pass_count,
        fail_count=fail_count,
        gaps=gaps,
        recommendations=recommendations,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------

def _score_to_priority(score: int) -> Priority:
    """Determine gap priority based on article score."""
    if score < 20:
        return Priority.CRITICAL
    if score < 40:
        return Priority.HIGH
    if score < 60:
        return Priority.MEDIUM
    return Priority.LOW


def _priority_to_effort(priority: Priority) -> str:
    """Map priority to estimated effort timeline."""
    mapping = {
        Priority.CRITICAL: "court",
        Priority.HIGH: "court",
        Priority.MEDIUM: "moyen",
        Priority.LOW: "long",
    }
    return mapping[priority]


def analyze_gaps(article_scores: list[ArticleScore]) -> list[GapItem]:
    """Generate gap items for articles scoring below 50.

    Priority is assigned based on score thresholds:
    - < 20: CRITICAL
    - < 40: HIGH
    - < 60: MEDIUM
    - < 80: LOW

    Only articles with score < 50 are included as gaps.
    """
    gaps: list[GapItem] = []

    for a_score in article_scores:
        if a_score.score >= 50:
            continue

        priority = _score_to_priority(a_score.score)

        gap_parts = []
        if a_score.gaps:
            gap_parts.append(
                f"{len(a_score.gaps)} contr\u00f4le(s) manquant(s)"
            )
        if a_score.fail_count > 0:
            gap_parts.append(
                f"{a_score.fail_count} finding(s) \u00e0 rem\u00e9dier"
            )
        if not gap_parts:
            gap_parts.append("Aucune \u00e9vidence de conformit\u00e9")

        gap_description = (
            f"Article {a_score.article_id} ({a_score.title}) : "
            f"score {a_score.score}/100 \u2014 " + ", ".join(gap_parts)
        )

        recommended_action = (
            f"Mettre en \u0153uvre les mesures requises pour "
            f"{a_score.title.lower()}"
        )

        gaps.append(GapItem(
            article_id=a_score.article_id,
            article_title=a_score.title,
            gap_description=gap_description,
            priority=priority,
            recommended_action=recommended_action,
            estimated_effort=_priority_to_effort(priority),
        ))

    # Sort by priority (CRITICAL first)
    priority_order = {
        Priority.CRITICAL: 0,
        Priority.HIGH: 1,
        Priority.MEDIUM: 2,
        Priority.LOW: 3,
    }
    gaps.sort(key=lambda g: priority_order[g.priority])

    return gaps


# ---------------------------------------------------------------------------
# Action plan generation
# ---------------------------------------------------------------------------

_ARTICLE_RESPONSIBLE: dict[str, str] = {
    "art21_2a": "RSSI",
    "art21_2b": "RSSI",
    "art21_2c": "DSI",
    "art21_2d": "DSI",
    "art21_2e": "IT",
    "art21_2f": "RSSI",
    "art21_2g": "RSSI",
    "art21_2h": "IT",
    "art21_2i": "DSI",
    "art21_2j": "IT",
}

_PRIORITY_TO_DEADLINE: dict[Priority, str] = {
    Priority.CRITICAL: "imm\u00e9diat",
    Priority.HIGH: "court_terme",
    Priority.MEDIUM: "moyen_terme",
    Priority.LOW: "moyen_terme",
}

_PRIORITY_TO_COST: dict[Priority, str] = {
    Priority.CRITICAL: "\u00e9lev\u00e9",
    Priority.HIGH: "moyen",
    Priority.MEDIUM: "moyen",
    Priority.LOW: "faible",
}


def generate_action_plan(gaps: list[GapItem]) -> list[ActionItem]:
    """Generate prioritized action items from identified gaps.

    Each gap produces one action item with:
    - Responsible party based on article ownership
    - Deadline category based on priority
    - Estimated cost based on priority
    """
    actions: list[ActionItem] = []

    for gap in gaps:
        responsible = _ARTICLE_RESPONSIBLE.get(gap.article_id, "RSSI")
        deadline = _PRIORITY_TO_DEADLINE[gap.priority]
        cost = _PRIORITY_TO_COST[gap.priority]

        actions.append(ActionItem(
            priority=gap.priority,
            article_id=gap.article_id,
            action_fr=gap.recommended_action,
            responsible=responsible,
            deadline_category=deadline,
            estimated_cost=cost,
        ))

    return actions


# ---------------------------------------------------------------------------
# Controls detection from findings evidence
# ---------------------------------------------------------------------------

_CONTROL_DETECTION_RULES: dict[str, list[tuple[str, list[str]]]] = {
    # article_id -> list of (control_name, detection_keywords)
    "art21_2a": [
        ("politique de s\u00e9curit\u00e9", ["security policy", "politique de s\u00e9curit\u00e9", "politique s\u00e9curit\u00e9"]),
        ("analyse de risques", ["risk analysis", "risk assessment", "analyse de risques", "analyse des risques"]),
        ("inventaire des actifs", ["asset inventory", "inventaire des actifs", "inventaire actifs", "cmdb"]),
        ("classification des actifs", ["asset classification", "classification des actifs", "data classification"]),
        ("traitement des risques", ["risk treatment", "traitement des risques", "risk mitigation"]),
        ("registre des risques", ["risk register", "registre des risques"]),
    ],
    "art21_2b": [
        ("proc\u00e9dure de gestion des incidents", ["incident management", "incident response", "gestion des incidents"]),
        ("d\u00e9tection des incidents", ["detection", "d\u00e9tection", "monitoring", "siem", "sigma"]),
        ("classification des incidents", ["incident classification", "classification des incidents", "triage"]),
        ("notification des incidents", ["incident notification", "notification", "alerting"]),
        ("analyse post-incident", ["post-incident", "post-mortem", "lessons learned", "retour d'exp\u00e9rience"]),
        ("plan de r\u00e9ponse aux incidents", ["incident response plan", "plan de r\u00e9ponse", "playbook"]),
    ],
    "art21_2c": [
        ("plan de continuit\u00e9 d'activit\u00e9", ["business continuity", "pca", "bcp", "continuit\u00e9"]),
        ("plan de reprise d'activit\u00e9", ["disaster recovery", "pra", "drp", "reprise"]),
        ("sauvegardes", ["backup", "sauvegarde"]),
        ("tests de restauration", ["restore test", "test de restauration", "recovery test"]),
        ("gestion de crise", ["crisis management", "gestion de crise"]),
        ("communication de crise", ["crisis communication", "communication de crise"]),
    ],
    "art21_2d": [
        ("\u00e9valuation des fournisseurs", ["vendor assessment", "\u00e9valuation fournisseur", "supplier evaluation"]),
        ("clauses de s\u00e9curit\u00e9 contractuelles", ["security clauses", "clauses contractuelles", "contract security"]),
        ("audit des fournisseurs", ["vendor audit", "audit fournisseur", "supplier audit"]),
        ("gestion des d\u00e9pendances", ["dependency management", "gestion des d\u00e9pendances", "sbom"]),
        ("suivi des vuln\u00e9rabilit\u00e9s tierces", ["third-party vulnerability", "vuln\u00e9rabilit\u00e9 tierce", "supply chain"]),
    ],
    "art21_2e": [
        ("d\u00e9veloppement s\u00e9curis\u00e9", ["secure development", "d\u00e9veloppement s\u00e9curis\u00e9", "sdlc", "devsecops"]),
        ("revue de code", ["code review", "revue de code", "sast"]),
        ("tests de s\u00e9curit\u00e9", ["security testing", "test de s\u00e9curit\u00e9", "pentest", "dast"]),
        ("gestion des vuln\u00e9rabilit\u00e9s", ["vulnerability management", "gestion des vuln\u00e9rabilit\u00e9s", "vuln scan"]),
        ("patch management", ["patch management", "gestion des patchs", "mise \u00e0 jour"]),
        ("configuration s\u00e9curis\u00e9e", ["secure configuration", "hardening", "durcissement", "baseline"]),
    ],
    "art21_2f": [
        ("indicateurs de performance", ["kpi", "indicator", "indicateur", "metric"]),
        ("audits r\u00e9guliers", ["regular audit", "audit r\u00e9gulier", "audit periodique"]),
        ("tests d'intrusion", ["penetration test", "pentest", "test d'intrusion"]),
        ("revue de direction", ["management review", "revue de direction"]),
        ("am\u00e9lioration continue", ["continuous improvement", "am\u00e9lioration continue"]),
        ("tableaux de bord", ["dashboard", "tableau de bord", "reporting"]),
    ],
    "art21_2g": [
        ("programme de sensibilisation", ["awareness program", "sensibilisation", "security awareness"]),
        ("formation cybers\u00e9curit\u00e9", ["cybersecurity training", "formation", "training"]),
        ("politique de mots de passe", ["password policy", "politique de mots de passe", "password"]),
        ("hygi\u00e8ne num\u00e9rique", ["cyber hygiene", "hygi\u00e8ne", "hygiene"]),
        ("exercices de phishing", ["phishing exercise", "phishing simulation", "exercice phishing"]),
    ],
    "art21_2h": [
        ("politique de chiffrement", ["encryption policy", "politique de chiffrement", "cryptographic policy"]),
        ("gestion des cl\u00e9s", ["key management", "gestion des cl\u00e9s", "kms"]),
        ("chiffrement des donn\u00e9es au repos", ["encryption at rest", "chiffrement au repos", "data at rest"]),
        ("chiffrement des donn\u00e9es en transit", ["encryption in transit", "tls", "https", "ssl", "chiffrement en transit"]),
        ("certificats et PKI", ["certificate", "certificat", "pki", "x509"]),
    ],
    "art21_2i": [
        ("politique de contr\u00f4le d'acc\u00e8s", ["access control", "contr\u00f4le d'acc\u00e8s", "access policy"]),
        ("gestion des identit\u00e9s", ["identity management", "iam", "gestion des identit\u00e9s"]),
        ("revue des acc\u00e8s", ["access review", "revue des acc\u00e8s", "access recertification"]),
        ("principe du moindre privil\u00e8ge", ["least privilege", "moindre privil\u00e8ge", "minimal access"]),
        ("gestion des d\u00e9parts", ["offboarding", "gestion des d\u00e9parts", "account deprovisioning"]),
        ("s\u00e9curit\u00e9 RH", ["hr security", "s\u00e9curit\u00e9 rh", "personnel security"]),
    ],
    "art21_2j": [
        ("authentification multi-facteur", ["mfa", "multi-factor", "multi-facteur", "2fa"]),
        ("politique MFA", ["mfa policy", "politique mfa"]),
        ("communications s\u00e9curis\u00e9es", ["secure communication", "communications s\u00e9curis\u00e9es", "encrypted messaging"]),
        ("syst\u00e8me de communication d'urgence", ["emergency communication", "communication d'urgence"]),
    ],
}


def determine_controls_met(
    findings: list[SecurityFinding],
) -> dict[str, list[str]]:
    """Determine which controls are met based on findings evidence.

    Analyses finding titles, descriptions, and metadata to detect evidence
    of controls being in place.  A finding from a scanning tool indicates
    that the corresponding detection/assessment control exists.

    Returns a dict mapping article_id -> list of controls met.
    """
    controls_met: dict[str, list[str]] = {aid: [] for aid in NIS2_ARTICLES}

    # Aggregate all finding text for matching
    all_text = ""
    for f in findings:
        all_text += f" {f.title} {f.description} {f.remediation}"
        for v in f.metadata.values():
            if isinstance(v, str):
                all_text += f" {v}"
    all_text_lower = all_text.lower()

    # Source-based control detection: having findings from a source implies
    # that the related detection/assessment controls are in place
    source_control_evidence: dict[str, list[str]] = {
        "vuln_scan": [
            ("art21_2a", "analyse de risques"),
            ("art21_2e", "gestion des vuln\u00e9rabilit\u00e9s"),
            ("art21_2e", "tests de s\u00e9curit\u00e9"),
        ],
        "soc_monitor": [
            ("art21_2b", "d\u00e9tection des incidents"),
            ("art21_2b", "proc\u00e9dure de gestion des incidents"),
        ],
        "secrets": [
            ("art21_2h", "gestion des cl\u00e9s"),
        ],
        "phishing": [
            ("art21_2g", "exercices de phishing"),
        ],
        "email_audit": [
            ("art21_2g", "programme de sensibilisation"),
        ],
        "cloud_posture": [
            ("art21_2a", "inventaire des actifs"),
            ("art21_2h", "chiffrement des donn\u00e9es en transit"),
        ],
        "darkweb": [
            ("art21_2i", "gestion des identit\u00e9s"),
        ],
    }

    seen_sources: set[str] = set()
    for f in findings:
        src = f.source.value
        if src not in seen_sources:
            seen_sources.add(src)
            for article_id, control in source_control_evidence.get(src, []):
                if control not in controls_met[article_id]:
                    controls_met[article_id].append(control)

    # Keyword-based control detection from findings content
    for article_id, rules in _CONTROL_DETECTION_RULES.items():
        for control_name, detection_keywords in rules:
            if control_name in controls_met[article_id]:
                continue  # already detected via source
            for kw in detection_keywords:
                if kw.lower() in all_text_lower:
                    controls_met[article_id].append(control_name)
                    break

    return controls_met


# ---------------------------------------------------------------------------
# Data aggregation -- fetch findings from PostgreSQL
# ---------------------------------------------------------------------------

def _parse_period(period: str) -> str:
    """Convert a period string like 'last_30d' to a PostgreSQL interval."""
    match = re.match(r"last_(\d+)(d|h|m)", period)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        unit_map = {"d": "days", "h": "hours", "m": "minutes"}
        return f"{amount} {unit_map.get(unit, 'days')}"
    return "30 days"


async def _query_table(table: str, interval: str) -> list[dict]:
    """Run a SELECT against a table via psql in the threatclaw-db container."""
    query = (
        f"SELECT row_to_json(t) FROM "
        f"(SELECT * FROM {table} "
        f"WHERE created_at >= NOW() - INTERVAL '{interval}' "
        f"ORDER BY created_at DESC) t;"
    )
    cmd = [
        "docker", "exec", "threatclaw-db",
        "psql", "-U", "threatclaw", "-d", "threatclaw",
        "-t", "-A", "-c", query,
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        return []

    records: list[dict] = []
    for line in stdout.decode(errors="replace").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records


def _row_to_finding(row: dict, source: FindingSource) -> SecurityFinding:
    """Convert a database row dict into a SecurityFinding."""
    return SecurityFinding(
        source=source,
        severity=str(row.get("severity", row.get("criticality", "medium"))).lower(),
        title=str(row.get("title", row.get("rule_name", row.get("cve_id", "Unknown")))),
        description=str(row.get("description", "")),
        remediation=str(row.get("remediation", "")),
        date=str(row.get("created_at", row.get("timestamp", row.get("date", "")))),
        metadata={
            k: v for k, v in row.items()
            if k not in ("title", "description", "severity", "remediation",
                         "created_at", "timestamp", "date", "criticality")
        },
    )


async def fetch_all_findings(period: str) -> list[SecurityFinding]:
    """Fetch findings from all source tables in PostgreSQL.

    Queries sigma_alerts, cloud_findings, and logs tables, then converts
    each row into a SecurityFinding with the appropriate source type.
    """
    interval = _parse_period(period)

    table_source_map = [
        ("sigma_alerts", FindingSource.SOC_MONITOR),
        ("cloud_findings", FindingSource.CLOUD_POSTURE),
        ("vuln_findings", FindingSource.VULN_SCAN),
        ("secret_findings", FindingSource.SECRETS),
        ("email_findings", FindingSource.EMAIL_AUDIT),
        ("darkweb_findings", FindingSource.DARKWEB),
        ("phishing_findings", FindingSource.PHISHING),
    ]

    tasks = [_query_table(table, interval) for table, _ in table_source_map]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[SecurityFinding] = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            continue
        source = table_source_map[i][1]
        for row in result:
            findings.append(_row_to_finding(row, source))

    return findings


# ---------------------------------------------------------------------------
# Maturity level helpers
# ---------------------------------------------------------------------------

_MATURITY_LABELS: dict[int, str] = {
    1: "Initial",
    2: "G\u00e9r\u00e9",
    3: "D\u00e9fini",
    4: "Mesur\u00e9",
    5: "Optimis\u00e9",
}


def _overall_maturity(scores: list[ArticleScore]) -> int:
    """Compute overall maturity as the rounded average of article maturities."""
    if not scores:
        return 1
    total = sum(s.maturity_level for s in scores)
    return max(1, min(5, round(total / len(scores))))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point -- full NIS2 Art.21 compliance pipeline.

    Pipeline:
    1. Fetch all security findings from data sources
    2. Map each finding to relevant NIS2 articles
    3. Determine which controls are evidenced by findings
    4. Calculate compliance score per article
    5. Perform gap analysis
    6. Generate action plan
    7. Produce structured compliance report
    """
    try:
        # 1. Fetch findings
        findings = await fetch_all_findings(input.period)

        # 2. Map findings to articles
        article_findings: dict[str, list[SecurityFinding]] = {
            aid: [] for aid in NIS2_ARTICLES
        }
        for finding in findings:
            mapped = map_finding_to_articles(finding)
            for article_id in mapped:
                if article_id in article_findings:
                    article_findings[article_id].append(finding)

        # 3. Determine controls met
        controls_met = determine_controls_met(findings)

        # 4. Calculate scores per article
        article_scores: list[ArticleScore] = []
        for article_id, article in NIS2_ARTICLES.items():
            a_findings = article_findings[article_id]
            a_controls = controls_met.get(article_id, [])
            score = calculate_article_score(article, a_findings, a_controls)
            article_scores.append(score)

        # 5. Gap analysis
        gaps = analyze_gaps(article_scores)

        # 6. Action plan
        action_plan: list[ActionItem] = []
        if input.include_recommendations:
            action_plan = generate_action_plan(gaps)

        # 7. Build report
        covered = sum(1 for s in article_scores if s.score > 0)
        uncovered = len(NIS2_ARTICLES) - covered
        overall = (
            int(sum(s.score for s in article_scores) / len(article_scores))
            if article_scores else 0
        )
        maturity = _overall_maturity(article_scores)

        maturity_label = _MATURITY_LABELS.get(maturity, "Initial")
        summary_fr = (
            f"Score global de conformit\u00e9 NIS2 : {overall}/100 "
            f"(maturit\u00e9 : {maturity_label}). "
            f"{covered} article(s) couvert(s), "
            f"{uncovered} article(s) non couvert(s). "
            f"{len(findings)} finding(s) analys\u00e9(s), "
            f"{len(gaps)} \u00e9cart(s) identifi\u00e9(s), "
            f"{len(action_plan)} action(s) recommand\u00e9e(s)."
        )

        report = ComplianceReport(
            overall_score=overall,
            article_scores=article_scores,
            gaps=gaps,
            action_plan=action_plan,
            total_findings=len(findings),
            covered_articles=covered,
            uncovered_articles=uncovered,
            maturity_level=maturity,
            summary_fr=summary_fr,
        )

        return SkillOutput(success=True, report=report)

    except Exception as e:
        return SkillOutput(success=False, error=f"Erreur NIS2 : {e}")
