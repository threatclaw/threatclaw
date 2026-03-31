"""
skill-report-gen -- Security report generation
PDF reports in French for RSSI/COMEX — NIS2/ISO 27001 compliance

Aggregates data from all other ThreatClaw skills (vuln-scan, soc-monitor,
cloud-posture, darkweb, secrets) and produces structured HTML/PDF reports
for executive (COMEX), technical (IT), and compliance audiences.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPORT_OUTPUT_DIR = os.environ.get(
    "THREATCLAW_REPORT_DIR", "/var/lib/threatclaw/reports"
)

# ThreatClaw branding
COLOR_PRIMARY = "#1a1a2e"
COLOR_ACCENT = "#e94560"
COLOR_DARK = "#16213e"
COLOR_LIGHT = "#f5f5f5"
COLOR_SUCCESS = "#27ae60"
COLOR_WARNING = "#f39c12"
COLOR_DANGER = "#e74c3c"

# Score weights for overall security score calculation
SCORE_WEIGHTS = {
    "vuln_scan": 0.30,
    "cloud_posture": 0.25,
    "soc_alerts": 0.20,
    "secrets": 0.15,
    "darkweb": 0.10,
}

# Period mapping for SQL interval generation
PERIOD_TO_INTERVAL = {
    "last_7d": "7 days",
    "last_30d": "30 days",
    "last_quarter": "90 days",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReportType(Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    FULL = "full"


class ReportFramework(Enum):
    NIS2 = "nis2"
    ISO27001 = "iso27001"
    BOTH = "both"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ReportSection:
    title: str
    content: str  # markdown or HTML content
    score: Optional[float] = None  # 0-100 optional score
    findings_count: int = 0
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    subsections: list["ReportSection"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class FindingSummary:
    source_skill: str
    severity: str
    count: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportData:
    title: str
    subtitle: str
    date: str
    period: str
    framework: str
    overall_score: float = 0.0
    sections: list[ReportSection] = field(default_factory=list)
    finding_summaries: list[FindingSummary] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class SkillInput:
    report_type: ReportType = ReportType.EXECUTIVE
    period: str = "last_7d"
    framework: ReportFramework = ReportFramework.NIS2
    include_sections: list[str] = field(default_factory=lambda: ["all"])
    language: str = "fr"
    client_name: str = ""
    client_siren: str = ""


@dataclass
class SkillOutput:
    success: bool = False
    pdf_path: str = ""
    html_content: str = ""
    report_data: Optional[ReportData] = None
    summary: str = ""
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Database helpers (docker exec psql pattern)
# ---------------------------------------------------------------------------

async def _run_psql_query(query: str) -> list[dict]:
    """Execute a SQL query via ``docker exec`` against the threatclaw-db
    container and return the result rows as dicts (using ``row_to_json``).
    """
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
        err_text = stderr.decode(errors="replace").strip()
        raise RuntimeError(f"psql query failed (rc={proc.returncode}): {err_text}")

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


def _interval_for_period(period: str) -> str:
    """Return a PostgreSQL INTERVAL literal for a given period key."""
    return PERIOD_TO_INTERVAL.get(period, "7 days")


# ---------------------------------------------------------------------------
# Data aggregation functions
# ---------------------------------------------------------------------------

async def fetch_vuln_scan_summary(period: str) -> dict:
    """Count vulnerabilities by severity from the ``findings`` table.

    Returns a dict with keys: critical, high, medium, low, total, score.
    """
    interval = _interval_for_period(period)
    query = (
        "SELECT row_to_json(t) FROM ("
        "SELECT "
        "  COUNT(*) FILTER (WHERE severity = 'critical') AS critical, "
        "  COUNT(*) FILTER (WHERE severity = 'high') AS high, "
        "  COUNT(*) FILTER (WHERE severity = 'medium') AS medium, "
        "  COUNT(*) FILTER (WHERE severity = 'low') AS low, "
        "  COUNT(*) AS total "
        f"FROM findings WHERE timestamp >= NOW() - INTERVAL '{interval}'"
        ") t;"
    )
    rows = await _run_psql_query(query)
    if rows:
        row = rows[0]
        total = row.get("total", 0)
        critical = row.get("critical", 0)
        high = row.get("high", 0)
        # Score: start at 100, subtract weighted penalties
        penalty = critical * 10 + high * 5 + row.get("medium", 0) * 2 + row.get("low", 0) * 0.5
        score = max(0.0, 100.0 - penalty)
        row["score"] = round(score, 1)
        return row
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "score": 100.0}


async def fetch_soc_alerts_summary(period: str) -> dict:
    """Count alerts from the ``sigma_alerts`` table.

    Returns a dict with keys: critical, high, medium, low, total, score.
    """
    interval = _interval_for_period(period)
    query = (
        "SELECT row_to_json(t) FROM ("
        "SELECT "
        "  COUNT(*) FILTER (WHERE severity = 'critical') AS critical, "
        "  COUNT(*) FILTER (WHERE severity = 'high') AS high, "
        "  COUNT(*) FILTER (WHERE severity = 'medium') AS medium, "
        "  COUNT(*) FILTER (WHERE severity = 'low') AS low, "
        "  COUNT(*) AS total "
        f"FROM sigma_alerts WHERE timestamp >= NOW() - INTERVAL '{interval}'"
        ") t;"
    )
    rows = await _run_psql_query(query)
    if rows:
        row = rows[0]
        critical = row.get("critical", 0)
        high = row.get("high", 0)
        penalty = critical * 15 + high * 8 + row.get("medium", 0) * 3 + row.get("low", 0) * 1
        row["score"] = round(max(0.0, 100.0 - penalty), 1)
        return row
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "score": 100.0}


async def fetch_cloud_posture_summary() -> dict:
    """Fetch the latest cloud posture score from ``cloud_findings``.

    Returns a dict with keys: score, pass_count, fail_count, total, severity breakdown.
    """
    query = (
        "SELECT row_to_json(t) FROM ("
        "SELECT "
        "  COUNT(*) FILTER (WHERE status = 'PASS') AS pass_count, "
        "  COUNT(*) FILTER (WHERE status = 'FAIL') AS fail_count, "
        "  COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'FAIL') AS critical, "
        "  COUNT(*) FILTER (WHERE severity = 'high' AND status = 'FAIL') AS high, "
        "  COUNT(*) FILTER (WHERE severity = 'medium' AND status = 'FAIL') AS medium, "
        "  COUNT(*) FILTER (WHERE severity = 'low' AND status = 'FAIL') AS low, "
        "  COUNT(*) AS total "
        "FROM cloud_findings"
        ") t;"
    )
    rows = await _run_psql_query(query)
    if rows:
        row = rows[0]
        total = row.get("total", 0)
        pass_count = row.get("pass_count", 0)
        if total > 0:
            row["score"] = round((pass_count / total) * 100, 1)
        else:
            row["score"] = 100.0
        return row
    return {
        "pass_count": 0, "fail_count": 0, "critical": 0,
        "high": 0, "medium": 0, "low": 0, "total": 0, "score": 100.0,
    }


async def fetch_darkweb_summary(period: str) -> dict:
    """Count dark web breach detections from the ``darkweb_breaches`` table.

    Returns a dict with keys: breach_count, critical, high, total_pwned, score.
    """
    interval = _interval_for_period(period)
    query = (
        "SELECT row_to_json(t) FROM ("
        "SELECT "
        "  COUNT(*) AS breach_count, "
        "  COUNT(*) FILTER (WHERE criticality = 'critical') AS critical, "
        "  COUNT(*) FILTER (WHERE criticality = 'high') AS high, "
        "  COALESCE(SUM(pwn_count), 0) AS total_pwned "
        f"FROM darkweb_breaches WHERE detected_at >= NOW() - INTERVAL '{interval}'"
        ") t;"
    )
    rows = await _run_psql_query(query)
    if rows:
        row = rows[0]
        breach_count = row.get("breach_count", 0)
        critical = row.get("critical", 0)
        high = row.get("high", 0)
        penalty = critical * 20 + high * 10 + max(0, breach_count - critical - high) * 3
        row["score"] = round(max(0.0, 100.0 - penalty), 1)
        return row
    return {"breach_count": 0, "critical": 0, "high": 0, "total_pwned": 0, "score": 100.0}


async def fetch_secrets_summary(period: str) -> dict:
    """Count leaked secrets from the ``secret_findings`` table.

    Returns a dict with keys: critical, high, medium, low, total, score.
    """
    interval = _interval_for_period(period)
    query = (
        "SELECT row_to_json(t) FROM ("
        "SELECT "
        "  COUNT(*) FILTER (WHERE criticality = 'critical') AS critical, "
        "  COUNT(*) FILTER (WHERE criticality = 'high') AS high, "
        "  COUNT(*) FILTER (WHERE criticality = 'medium') AS medium, "
        "  COUNT(*) FILTER (WHERE criticality = 'low') AS low, "
        "  COUNT(*) AS total "
        f"FROM secret_findings WHERE detected_at >= NOW() - INTERVAL '{interval}'"
        ") t;"
    )
    rows = await _run_psql_query(query)
    if rows:
        row = rows[0]
        critical = row.get("critical", 0)
        high = row.get("high", 0)
        penalty = critical * 20 + high * 10 + row.get("medium", 0) * 3 + row.get("low", 0) * 1
        row["score"] = round(max(0.0, 100.0 - penalty), 1)
        return row
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "score": 100.0}


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------

def calculate_overall_score(
    vuln_data: dict,
    cloud_data: dict,
    soc_data: dict,
    secrets_data: dict,
    darkweb_data: dict,
) -> float:
    """Compute a weighted average security score across all data sources.

    Weights:
        vuln scan   : 30%
        cloud posture: 25%
        SOC alerts  : 20%
        secrets     : 15%
        darkweb     : 10%

    Each source contributes a sub-score in [0, 100].  If a source has no
    data (score key missing), it defaults to 100 (no issues detected).
    """
    vuln_score = vuln_data.get("score", 100.0)
    cloud_score = cloud_data.get("score", 100.0)
    soc_score = soc_data.get("score", 100.0)
    secrets_score = secrets_data.get("score", 100.0)
    darkweb_score = darkweb_data.get("score", 100.0)

    weighted = (
        vuln_score * SCORE_WEIGHTS["vuln_scan"]
        + cloud_score * SCORE_WEIGHTS["cloud_posture"]
        + soc_score * SCORE_WEIGHTS["soc_alerts"]
        + secrets_score * SCORE_WEIGHTS["secrets"]
        + darkweb_score * SCORE_WEIGHTS["darkweb"]
    )

    return round(max(0.0, min(100.0, weighted)), 1)


# ---------------------------------------------------------------------------
# Report content builders
# ---------------------------------------------------------------------------

def _score_label(score: float) -> str:
    """Return a French label for a numeric score."""
    if score >= 80:
        return "Bon"
    if score >= 60:
        return "Acceptable"
    if score >= 40:
        return "Insuffisant"
    return "Critique"


def _score_color(score: float) -> str:
    """Return a CSS color for a score value."""
    if score >= 80:
        return COLOR_SUCCESS
    if score >= 60:
        return COLOR_WARNING
    return COLOR_DANGER


def _severity_badge(severity: str) -> str:
    colors = {
        "critical": COLOR_DANGER,
        "high": "#e67e22",
        "medium": COLOR_WARNING,
        "low": COLOR_SUCCESS,
    }
    color = colors.get(severity.lower(), "#999")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em;">{severity.upper()}</span>'


def build_executive_report(data: ReportData) -> str:
    """Generate HTML content for an executive (COMEX/RSSI) audience.

    Sections:
        1. Synthese executive avec score global
        2. Score de securite global (gauge visualization description)
        3. Top 5 risques critiques
        4. Evolution vs periode precedente
        5. Recommandations prioritaires (top 5)
    """
    score = data.overall_score
    label = _score_label(score)
    color = _score_color(score)

    # --- Section 1: Synthese executive ---
    html = f"""
    <section class="report-section" id="synthese">
        <h2>1. Synth\u00e8se ex\u00e9cutive</h2>
        <p>Ce rapport couvre la p\u00e9riode <strong>{data.period}</strong> et pr\u00e9sente
        l'\u00e9tat de s\u00e9curit\u00e9 global de l'organisation.</p>
        <div class="score-card" style="text-align:center;padding:20px;background:{COLOR_DARK};color:#fff;border-radius:8px;margin:20px 0;">
            <h3 style="margin:0;">Score de s\u00e9curit\u00e9 global</h3>
            <div style="font-size:3em;font-weight:bold;color:{color};">{score:.0f}/100</div>
            <div style="font-size:1.2em;color:{color};">{label}</div>
        </div>
        <table class="summary-table">
            <tr><th>Indicateur</th><th>Valeur</th></tr>
            <tr><td>Total des findings</td><td><strong>{data.total_findings}</strong></td></tr>
            <tr><td>Critiques</td><td style="color:{COLOR_DANGER};"><strong>{data.critical_count}</strong></td></tr>
            <tr><td>\u00c9lev\u00e9s</td><td style="color:#e67e22;"><strong>{data.high_count}</strong></td></tr>
            <tr><td>Moyens</td><td style="color:{COLOR_WARNING};"><strong>{data.medium_count}</strong></td></tr>
            <tr><td>Faibles</td><td><strong>{data.low_count}</strong></td></tr>
        </table>
    </section>
    """

    # --- Section 2: Score de securite global ---
    html += f"""
    <section class="report-section" id="score-global">
        <h2>2. Score de s\u00e9curit\u00e9 global</h2>
        <p>Le score de s\u00e9curit\u00e9 est calcul\u00e9 selon une moyenne pond\u00e9r\u00e9e de cinq axes :</p>
        <ul>
            <li>Scan de vuln\u00e9rabilit\u00e9s (30%)</li>
            <li>Posture cloud (25%)</li>
            <li>Alertes SOC (20%)</li>
            <li>D\u00e9tection de secrets (15%)</li>
            <li>Surveillance dark web (10%)</li>
        </ul>
        <div class="gauge-description">
            <p>Score actuel : <strong style="color:{color};">{score:.0f}/100 — {label}</strong></p>
        </div>
    </section>
    """

    # --- Section 3: Top 5 risques critiques ---
    critical_findings = [
        fs for fs in data.finding_summaries if fs.severity == "critical"
    ][:5]
    html += """
    <section class="report-section" id="top-risques">
        <h2>3. Top 5 risques critiques</h2>
    """
    if critical_findings:
        html += '<table class="findings-table"><tr><th>Source</th><th>S\u00e9v\u00e9rit\u00e9</th><th>Nombre</th><th>Description</th></tr>'
        for fs in critical_findings:
            html += f'<tr><td>{fs.source_skill}</td><td>{_severity_badge(fs.severity)}</td><td>{fs.count}</td><td>{fs.description}</td></tr>'
        html += "</table>"
    else:
        html += "<p>Aucun risque critique d\u00e9tect\u00e9 sur cette p\u00e9riode.</p>"
    html += "</section>"

    # --- Section 4: Evolution ---
    html += """
    <section class="report-section" id="evolution">
        <h2>4. \u00c9volution vs p\u00e9riode pr\u00e9c\u00e9dente</h2>
        <p><em>L'analyse comparative avec la p\u00e9riode pr\u00e9c\u00e9dente sera disponible
        apr\u00e8s accumulation de donn\u00e9es historiques suffisantes.</em></p>
    </section>
    """

    # --- Section 5: Recommandations prioritaires ---
    html += """
    <section class="report-section" id="recommandations">
        <h2>5. Recommandations prioritaires</h2>
    """
    top_recs = data.recommendations[:5]
    if top_recs:
        html += "<ol>"
        for rec in top_recs:
            html += f"<li>{rec}</li>"
        html += "</ol>"
    else:
        html += "<p>Aucune recommandation sp\u00e9cifique pour cette p\u00e9riode.</p>"
    html += "</section>"

    return html


def build_technical_report(data: ReportData) -> str:
    """Generate HTML content for a technical (IT/SOC) audience.

    Includes all findings by category, detailed vulnerability list,
    SOC alert analysis, and cloud posture details.
    """
    html = """
    <section class="report-section" id="tech-overview">
        <h2>1. Vue d'ensemble technique</h2>
    """
    html += f"""
        <p>P\u00e9riode d'analyse : <strong>{data.period}</strong></p>
        <p>Total des findings : <strong>{data.total_findings}</strong></p>
        <table class="summary-table">
            <tr><th>S\u00e9v\u00e9rit\u00e9</th><th>Nombre</th></tr>
            <tr><td>{_severity_badge("critical")}</td><td>{data.critical_count}</td></tr>
            <tr><td>{_severity_badge("high")}</td><td>{data.high_count}</td></tr>
            <tr><td>{_severity_badge("medium")}</td><td>{data.medium_count}</td></tr>
            <tr><td>{_severity_badge("low")}</td><td>{data.low_count}</td></tr>
        </table>
    </section>
    """

    # --- Section 2: Findings par categorie ---
    html += """
    <section class="report-section" id="findings-par-categorie">
        <h2>2. Findings par cat\u00e9gorie</h2>
    """
    # Group by source_skill
    by_source: dict[str, list[FindingSummary]] = {}
    for fs in data.finding_summaries:
        by_source.setdefault(fs.source_skill, []).append(fs)

    for source, summaries in by_source.items():
        html += f"<h3>{source}</h3>"
        html += '<table class="findings-table"><tr><th>S\u00e9v\u00e9rit\u00e9</th><th>Nombre</th><th>Description</th></tr>'
        for fs in summaries:
            html += f'<tr><td>{_severity_badge(fs.severity)}</td><td>{fs.count}</td><td>{fs.description}</td></tr>'
        html += "</table>"

    if not by_source:
        html += "<p>Aucun finding d\u00e9tect\u00e9.</p>"
    html += "</section>"

    # --- Section 3: Analyse des alertes SOC ---
    html += """
    <section class="report-section" id="analyse-soc">
        <h2>3. Analyse des alertes SOC</h2>
    """
    soc_findings = [fs for fs in data.finding_summaries if fs.source_skill == "soc-monitor"]
    if soc_findings:
        html += '<table class="findings-table"><tr><th>S\u00e9v\u00e9rit\u00e9</th><th>Nombre</th><th>Description</th></tr>'
        for fs in soc_findings:
            html += f'<tr><td>{_severity_badge(fs.severity)}</td><td>{fs.count}</td><td>{fs.description}</td></tr>'
        html += "</table>"
    else:
        html += "<p>Aucune alerte SOC sur cette p\u00e9riode.</p>"
    html += "</section>"

    # --- Section 4: Posture cloud ---
    html += """
    <section class="report-section" id="posture-cloud">
        <h2>4. D\u00e9tails posture cloud</h2>
    """
    cloud_findings = [fs for fs in data.finding_summaries if fs.source_skill == "cloud-posture"]
    if cloud_findings:
        html += '<table class="findings-table"><tr><th>S\u00e9v\u00e9rit\u00e9</th><th>Nombre</th><th>Description</th></tr>'
        for fs in cloud_findings:
            html += f'<tr><td>{_severity_badge(fs.severity)}</td><td>{fs.count}</td><td>{fs.description}</td></tr>'
        html += "</table>"
    else:
        html += "<p>Aucun \u00e9cart de posture cloud d\u00e9tect\u00e9.</p>"
    html += "</section>"

    # --- Section 5: Detailed sections ---
    if data.sections:
        html += """
    <section class="report-section" id="details-sections">
        <h2>5. D\u00e9tail par section</h2>
    """
        for sec in data.sections:
            html += f"<h3>{sec.title}</h3>"
            html += f"<div>{sec.content}</div>"
            if sec.score is not None:
                html += f'<p>Score : <strong style="color:{_score_color(sec.score)};">{sec.score:.0f}/100</strong></p>'
        html += "</section>"

    return html


def build_compliance_report(data: ReportData, framework: str) -> str:
    """Generate HTML content for a compliance (NIS2 / ISO 27001) report.

    Sections:
        1. Score par article/controle
        2. GAP analysis
        3. Plan d'action recommande
    """
    framework_upper = framework.upper()

    # --- NIS2 articles ---
    nis2_articles = [
        ("Art.21 \u00a71", "Analyse des risques et s\u00e9curit\u00e9 des SI"),
        ("Art.21 \u00a72", "Gestion des incidents"),
        ("Art.21 \u00a73", "Continuit\u00e9 des activit\u00e9s et gestion de crise"),
        ("Art.21 \u00a74", "S\u00e9curit\u00e9 de la cha\u00eene d'approvisionnement"),
        ("Art.21 \u00a75", "S\u00e9curit\u00e9 des r\u00e9seaux"),
        ("Art.21 \u00a76", "Gestion des vuln\u00e9rabilit\u00e9s"),
        ("Art.21 \u00a77", "\u00c9valuation de l'efficacit\u00e9 des mesures"),
        ("Art.21 \u00a78", "Cryptographie et chiffrement"),
        ("Art.21 \u00a79", "S\u00e9curit\u00e9 RH et contr\u00f4le d'acc\u00e8s"),
        ("Art.21 \u00a710", "Authentification multi-facteur"),
    ]

    # --- ISO 27001 Annex A control families ---
    iso_controls = [
        ("A.5", "Politiques de s\u00e9curit\u00e9 de l'information"),
        ("A.6", "Organisation de la s\u00e9curit\u00e9 de l'information"),
        ("A.7", "S\u00e9curit\u00e9 des ressources humaines"),
        ("A.8", "Gestion des actifs"),
        ("A.9", "Contr\u00f4le d'acc\u00e8s"),
        ("A.10", "Cryptographie"),
        ("A.11", "S\u00e9curit\u00e9 physique et environnementale"),
        ("A.12", "S\u00e9curit\u00e9 li\u00e9e \u00e0 l'exploitation"),
        ("A.13", "S\u00e9curit\u00e9 des communications"),
        ("A.14", "Acquisition, d\u00e9veloppement et maintenance des syst\u00e8mes"),
        ("A.15", "Relations avec les fournisseurs"),
        ("A.16", "Gestion des incidents de s\u00e9curit\u00e9"),
        ("A.17", "Continuit\u00e9 d'activit\u00e9"),
        ("A.18", "Conformit\u00e9"),
    ]

    html = ""

    # Determine which frameworks to render
    show_nis2 = framework_upper in ("NIS2", "BOTH")
    show_iso = framework_upper in ("ISO27001", "BOTH")

    # --- Section 1: Score par article/controle ---
    html += f"""
    <section class="report-section" id="compliance-score">
        <h2>1. Score par article/contr\u00f4le — {framework_upper}</h2>
        <p>Score global de conformit\u00e9 : <strong style="color:{_score_color(data.overall_score)};">{data.overall_score:.0f}/100</strong></p>
    """

    if show_nis2:
        html += '<h3>NIS2 — Directive (UE) 2022/2555</h3>'
        html += '<table class="compliance-table"><tr><th>Article</th><th>Description</th><th>Score</th></tr>'
        for art_id, art_desc in nis2_articles:
            # Use overall score as placeholder per-article score (real per-article
            # scoring requires per-article finding data, which would come from
            # cloud-posture NIS2 mapping).
            section_score = data.overall_score
            color = _score_color(section_score)
            html += f'<tr><td>{art_id}</td><td>{art_desc}</td><td style="color:{color};font-weight:bold;">{section_score:.0f}%</td></tr>'
        html += "</table>"

    if show_iso:
        html += '<h3>ISO 27001:2022 — Annexe A</h3>'
        html += '<table class="compliance-table"><tr><th>Contr\u00f4le</th><th>Description</th><th>Score</th></tr>'
        for ctrl_id, ctrl_desc in iso_controls:
            section_score = data.overall_score
            color = _score_color(section_score)
            html += f'<tr><td>{ctrl_id}</td><td>{ctrl_desc}</td><td style="color:{color};font-weight:bold;">{section_score:.0f}%</td></tr>'
        html += "</table>"

    html += "</section>"

    # --- Section 2: GAP analysis ---
    html += """
    <section class="report-section" id="gap-analysis">
        <h2>2. Analyse des \u00e9carts (GAP Analysis)</h2>
    """
    if data.total_findings > 0:
        html += f"<p>{data.total_findings} \u00e9carts identifi\u00e9s dont {data.critical_count} critiques.</p>"
        if data.finding_summaries:
            html += '<table class="findings-table"><tr><th>Source</th><th>S\u00e9v\u00e9rit\u00e9</th><th>Nombre</th><th>Description</th></tr>'
            for fs in data.finding_summaries:
                html += f'<tr><td>{fs.source_skill}</td><td>{_severity_badge(fs.severity)}</td><td>{fs.count}</td><td>{fs.description}</td></tr>'
            html += "</table>"
    else:
        html += "<p>Aucun \u00e9cart identifi\u00e9. Posture de conformit\u00e9 satisfaisante.</p>"
    html += "</section>"

    # --- Section 3: Plan d'action recommande ---
    html += """
    <section class="report-section" id="plan-action">
        <h2>3. Plan d'action recommand\u00e9</h2>
    """
    if data.recommendations:
        html += '<table class="action-table"><tr><th>#</th><th>Action</th><th>Priorit\u00e9</th></tr>'
        for i, rec in enumerate(data.recommendations, 1):
            priority = "Haute" if i <= 3 else "Moyenne"
            html += f"<tr><td>{i}</td><td>{rec}</td><td>{priority}</td></tr>"
        html += "</table>"
    else:
        html += "<p>Aucune action corrective n\u00e9cessaire.</p>"
    html += "</section>"

    return html


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def render_html_report(
    report_data: ReportData,
    report_type: str,
    framework: str,
) -> str:
    """Generate a full HTML document with professional CSS styling.

    Includes:
        - ThreatClaw branding (primary #1a1a2e, accent #e94560, dark #16213e)
        - Header with logo placeholder, date, client info
        - Table of contents
        - Report sections (varies by report_type)
        - Footer with page numbers, confidentiality notice
    """
    # Determine the report title
    type_labels = {
        "executive": "Rapport Ex\u00e9cutif de S\u00e9curit\u00e9",
        "technical": "Rapport Technique de S\u00e9curit\u00e9",
        "compliance": f"Rapport de Conformit\u00e9 {framework.upper()}",
        "full": "Rapport Complet de S\u00e9curit\u00e9",
    }
    report_title = type_labels.get(report_type, "Rapport de S\u00e9curit\u00e9")

    # Build the body content depending on report type
    body_html = ""
    if report_type == "executive":
        body_html = build_executive_report(report_data)
    elif report_type == "technical":
        body_html = build_technical_report(report_data)
    elif report_type == "compliance":
        body_html = build_compliance_report(report_data, framework)
    elif report_type == "full":
        body_html = build_executive_report(report_data)
        body_html += '<hr style="margin:40px 0;">'
        body_html += build_technical_report(report_data)
        body_html += '<hr style="margin:40px 0;">'
        body_html += build_compliance_report(report_data, framework)
    else:
        body_html = build_executive_report(report_data)

    # Table of contents
    toc_html = """
    <nav id="toc">
        <h2>Table des mati\u00e8res</h2>
        <ul>
    """
    if report_type in ("executive", "full"):
        toc_html += """
            <li><a href="#synthese">Synth\u00e8se ex\u00e9cutive</a></li>
            <li><a href="#score-global">Score de s\u00e9curit\u00e9 global</a></li>
            <li><a href="#top-risques">Top 5 risques critiques</a></li>
            <li><a href="#evolution">\u00c9volution</a></li>
            <li><a href="#recommandations">Recommandations prioritaires</a></li>
        """
    if report_type in ("technical", "full"):
        toc_html += """
            <li><a href="#tech-overview">Vue d'ensemble technique</a></li>
            <li><a href="#findings-par-categorie">Findings par cat\u00e9gorie</a></li>
            <li><a href="#analyse-soc">Analyse SOC</a></li>
            <li><a href="#posture-cloud">Posture cloud</a></li>
        """
    if report_type in ("compliance", "full"):
        toc_html += """
            <li><a href="#compliance-score">Score de conformit\u00e9</a></li>
            <li><a href="#gap-analysis">Analyse des \u00e9carts</a></li>
            <li><a href="#plan-action">Plan d'action</a></li>
        """
    toc_html += """
        </ul>
    </nav>
    """

    # Full HTML document
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title} — ThreatClaw</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #333;
            line-height: 1.6;
            background: {COLOR_LIGHT};
        }}
        .report-container {{
            max-width: 900px;
            margin: 0 auto;
            background: #fff;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        /* Header */
        .report-header {{
            background: {COLOR_PRIMARY};
            color: #fff;
            padding: 30px 40px;
            border-bottom: 4px solid {COLOR_ACCENT};
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .report-header .logo {{
            font-size: 1.8em;
            font-weight: bold;
            color: {COLOR_ACCENT};
        }}
        .report-header .meta {{
            text-align: right;
            font-size: 0.9em;
        }}
        /* Table of contents */
        #toc {{
            background: {COLOR_DARK};
            color: #ccc;
            padding: 20px 30px;
            margin-bottom: 30px;
            border-radius: 6px;
        }}
        #toc h2 {{ color: {COLOR_ACCENT}; margin-bottom: 10px; }}
        #toc ul {{ list-style: none; padding-left: 0; }}
        #toc li {{ margin: 5px 0; }}
        #toc a {{ color: #aaa; text-decoration: none; }}
        #toc a:hover {{ color: {COLOR_ACCENT}; }}
        /* Sections */
        .report-section {{
            margin: 30px 0;
            padding: 20px 0;
            border-bottom: 1px solid #eee;
        }}
        .report-section h2 {{
            color: {COLOR_PRIMARY};
            border-left: 4px solid {COLOR_ACCENT};
            padding-left: 12px;
            margin-bottom: 15px;
        }}
        .report-section h3 {{
            color: {COLOR_DARK};
            margin: 15px 0 10px 0;
        }}
        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: {COLOR_PRIMARY};
            color: #fff;
            font-weight: 600;
        }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        /* Score card */
        .score-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
        }}
        /* Footer */
        .report-footer {{
            background: {COLOR_DARK};
            color: #aaa;
            padding: 20px 40px;
            font-size: 0.85em;
            display: flex;
            justify-content: space-between;
            border-top: 2px solid {COLOR_ACCENT};
            margin-top: 40px;
        }}
        .report-footer .confidentiality {{
            font-style: italic;
        }}
        /* Print */
        @media print {{
            body {{ background: #fff; }}
            .report-container {{ box-shadow: none; padding: 20px; }}
            .report-footer {{ position: fixed; bottom: 0; width: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <div>
            <div class="logo">ThreatClaw</div>
            <div>{report_title}</div>
        </div>
        <div class="meta">
            <div>Date : {report_data.date}</div>
            <div>P\u00e9riode : {report_data.period}</div>
            <div>Client : {report_data.title}</div>
        </div>
    </div>

    <div class="report-container">
        {toc_html}
        {body_html}
    </div>

    <div class="report-footer">
        <div class="confidentiality">
            CONFIDENTIEL — Ce document est destin\u00e9 exclusivement aux destinataires autoris\u00e9s.
            Toute diffusion, copie ou utilisation non autoris\u00e9e est strictement interdite.
        </div>
        <div>
            G\u00e9n\u00e9r\u00e9 par ThreatClaw &mdash; {report_data.date}
        </div>
    </div>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# PDF saving (stub — PDF rendering is TODO)
# ---------------------------------------------------------------------------

async def save_report_pdf(html: str, output_path: str) -> str:
    """Save the generated report.

    TODO: Integrate a proper HTML-to-PDF renderer (e.g. weasyprint or
    playwright) once the dependency is approved.  For now, the HTML is
    saved as-is and the path to the HTML file is returned.
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Write HTML content
    html_path = output_path.replace(".pdf", ".html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return html_path


# ---------------------------------------------------------------------------
# Recommendation generation
# ---------------------------------------------------------------------------

def _generate_recommendations(
    vuln_data: dict,
    cloud_data: dict,
    soc_data: dict,
    secrets_data: dict,
    darkweb_data: dict,
) -> list[str]:
    """Generate prioritised French recommendations based on aggregated data."""
    recs: list[str] = []

    # Critical vulns
    if vuln_data.get("critical", 0) > 0:
        recs.append(
            f"CRITIQUE : Corriger imm\u00e9diatement les {vuln_data['critical']} "
            f"vuln\u00e9rabilit\u00e9s critiques identifi\u00e9es par le scan."
        )

    # SOC critical alerts
    if soc_data.get("critical", 0) > 0:
        recs.append(
            f"CRITIQUE : Investiguer les {soc_data['critical']} alertes SOC critiques "
            f"et appliquer les mesures de rem\u00e9diation."
        )

    # Secrets detected
    if secrets_data.get("critical", 0) > 0:
        recs.append(
            f"\u00c9LEV\u00c9 : R\u00e9voquer imm\u00e9diatement les {secrets_data['critical']} "
            f"secrets critiques expos\u00e9s et effectuer une rotation des cl\u00e9s."
        )

    # Dark web breaches
    if darkweb_data.get("critical", 0) > 0:
        recs.append(
            f"\u00c9LEV\u00c9 : Notifier les utilisateurs affect\u00e9s par les {darkweb_data['critical']} "
            f"fuites critiques d\u00e9tect\u00e9es sur le dark web (Art.23 NIS2)."
        )

    # Cloud posture
    cloud_score = cloud_data.get("score", 100.0)
    if cloud_score < 70:
        recs.append(
            f"MOYEN : Am\u00e9liorer la posture cloud (score actuel : {cloud_score:.0f}/100). "
            f"Prioriser la correction des {cloud_data.get('critical', 0)} findings critiques."
        )

    # High vulns
    if vuln_data.get("high", 0) > 0:
        recs.append(
            f"MOYEN : Planifier la correction des {vuln_data['high']} "
            f"vuln\u00e9rabilit\u00e9s de s\u00e9v\u00e9rit\u00e9 \u00e9lev\u00e9e dans les 30 jours."
        )

    # MFA recommendation if SOC has auth alerts
    if soc_data.get("total", 0) > 10:
        recs.append(
            "MOYEN : Renforcer l'authentification multi-facteur (MFA) sur tous les "
            "comptes privil\u00e9gi\u00e9s conform\u00e9ment \u00e0 l'Art.21 \u00a710 NIS2."
        )

    # Generic improvements
    if not recs:
        recs.append(
            "FAIBLE : Maintenir la surveillance continue et planifier un audit "
            "de s\u00e9curit\u00e9 trimestriel."
        )

    return recs


# ---------------------------------------------------------------------------
# Finding summary builder
# ---------------------------------------------------------------------------

def _build_finding_summaries(
    vuln_data: dict,
    cloud_data: dict,
    soc_data: dict,
    secrets_data: dict,
    darkweb_data: dict,
) -> list[FindingSummary]:
    """Build a list of FindingSummary from aggregated data sources."""
    summaries: list[FindingSummary] = []

    # Vulnerability scan findings
    for sev in ("critical", "high", "medium", "low"):
        count = vuln_data.get(sev, 0)
        if count > 0:
            summaries.append(FindingSummary(
                source_skill="vuln-scan",
                severity=sev,
                count=count,
                description=f"{count} vuln\u00e9rabilit\u00e9(s) {sev} d\u00e9tect\u00e9e(s)",
            ))

    # SOC alerts
    for sev in ("critical", "high", "medium", "low"):
        count = soc_data.get(sev, 0)
        if count > 0:
            summaries.append(FindingSummary(
                source_skill="soc-monitor",
                severity=sev,
                count=count,
                description=f"{count} alerte(s) SOC {sev}",
            ))

    # Cloud posture
    for sev in ("critical", "high", "medium", "low"):
        count = cloud_data.get(sev, 0)
        if count > 0:
            summaries.append(FindingSummary(
                source_skill="cloud-posture",
                severity=sev,
                count=count,
                description=f"{count} \u00e9cart(s) posture cloud {sev}",
            ))

    # Secrets
    for sev in ("critical", "high", "medium", "low"):
        count = secrets_data.get(sev, 0)
        if count > 0:
            summaries.append(FindingSummary(
                source_skill="secrets",
                severity=sev,
                count=count,
                description=f"{count} secret(s) expos\u00e9(s) {sev}",
            ))

    # Dark web
    for sev in ("critical", "high"):
        count = darkweb_data.get(sev, 0)
        if count > 0:
            summaries.append(FindingSummary(
                source_skill="darkweb",
                severity=sev,
                count=count,
                description=f"{count} fuite(s) dark web {sev}",
            ))

    # Sort by severity order
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    summaries.sort(key=lambda s: severity_order.get(s.severity, 99))

    return summaries


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point.

    Pipeline:
        1. Aggregate data from all sources (PostgreSQL)
        2. Calculate overall security score
        3. Build finding summaries and recommendations
        4. Generate report content (HTML)
        5. Save report (HTML / PDF stub)
    """
    try:
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d %H:%M UTC")
        period = input.period
        framework = input.framework.value if isinstance(input.framework, ReportFramework) else str(input.framework)
        report_type = input.report_type.value if isinstance(input.report_type, ReportType) else str(input.report_type)

        # 1. Aggregate data from all sources
        vuln_data, soc_data, cloud_data, darkweb_data, secrets_data = await asyncio.gather(
            fetch_vuln_scan_summary(period),
            fetch_soc_alerts_summary(period),
            fetch_cloud_posture_summary(),
            fetch_darkweb_summary(period),
            fetch_secrets_summary(period),
        )

        # 2. Calculate overall score
        overall_score = calculate_overall_score(
            vuln_data, cloud_data, soc_data, secrets_data, darkweb_data,
        )

        # 3. Build finding summaries
        finding_summaries = _build_finding_summaries(
            vuln_data, cloud_data, soc_data, secrets_data, darkweb_data,
        )

        # Count totals
        total_findings = sum(fs.count for fs in finding_summaries)
        critical_count = sum(fs.count for fs in finding_summaries if fs.severity == "critical")
        high_count = sum(fs.count for fs in finding_summaries if fs.severity == "high")
        medium_count = sum(fs.count for fs in finding_summaries if fs.severity == "medium")
        low_count = sum(fs.count for fs in finding_summaries if fs.severity == "low")

        # 4. Generate recommendations
        recommendations = _generate_recommendations(
            vuln_data, cloud_data, soc_data, secrets_data, darkweb_data,
        )

        # Build report sections
        sections: list[ReportSection] = []
        sections.append(ReportSection(
            title="Scan de vuln\u00e9rabilit\u00e9s",
            content=f"{vuln_data.get('total', 0)} vuln\u00e9rabilit\u00e9s d\u00e9tect\u00e9es",
            score=vuln_data.get("score", 100.0),
            findings_count=vuln_data.get("total", 0),
            severity_breakdown={
                "critical": vuln_data.get("critical", 0),
                "high": vuln_data.get("high", 0),
                "medium": vuln_data.get("medium", 0),
                "low": vuln_data.get("low", 0),
            },
        ))
        sections.append(ReportSection(
            title="Posture cloud",
            content=f"Score posture cloud : {cloud_data.get('score', 100.0):.0f}/100",
            score=cloud_data.get("score", 100.0),
            findings_count=cloud_data.get("fail_count", 0),
            severity_breakdown={
                "critical": cloud_data.get("critical", 0),
                "high": cloud_data.get("high", 0),
                "medium": cloud_data.get("medium", 0),
                "low": cloud_data.get("low", 0),
            },
        ))
        sections.append(ReportSection(
            title="Alertes SOC",
            content=f"{soc_data.get('total', 0)} alertes SOC d\u00e9tect\u00e9es",
            score=soc_data.get("score", 100.0),
            findings_count=soc_data.get("total", 0),
            severity_breakdown={
                "critical": soc_data.get("critical", 0),
                "high": soc_data.get("high", 0),
                "medium": soc_data.get("medium", 0),
                "low": soc_data.get("low", 0),
            },
        ))
        sections.append(ReportSection(
            title="D\u00e9tection de secrets",
            content=f"{secrets_data.get('total', 0)} secrets expos\u00e9s d\u00e9tect\u00e9s",
            score=secrets_data.get("score", 100.0),
            findings_count=secrets_data.get("total", 0),
            severity_breakdown={
                "critical": secrets_data.get("critical", 0),
                "high": secrets_data.get("high", 0),
                "medium": secrets_data.get("medium", 0),
                "low": secrets_data.get("low", 0),
            },
        ))
        sections.append(ReportSection(
            title="Surveillance dark web",
            content=f"{darkweb_data.get('breach_count', 0)} fuites d\u00e9tect\u00e9es",
            score=darkweb_data.get("score", 100.0),
            findings_count=darkweb_data.get("breach_count", 0),
            severity_breakdown={
                "critical": darkweb_data.get("critical", 0),
                "high": darkweb_data.get("high", 0),
            },
        ))

        # Build ReportData
        client_name = input.client_name or "ThreatClaw Client"
        report_data = ReportData(
            title=client_name,
            subtitle=f"SIREN: {input.client_siren}" if input.client_siren else "",
            date=date_str,
            period=period,
            framework=framework,
            overall_score=overall_score,
            sections=sections,
            finding_summaries=finding_summaries,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            recommendations=recommendations,
        )

        # 5. Render HTML report
        html_content = render_html_report(report_data, report_type, framework)

        # 6. Save report
        timestamp_slug = now.strftime("%Y%m%d_%H%M%S")
        filename = f"rapport_{report_type}_{framework}_{timestamp_slug}"
        output_path = os.path.join(REPORT_OUTPUT_DIR, f"{filename}.pdf")
        saved_path = await save_report_pdf(html_content, output_path)

        summary = (
            f"Rapport {report_type} ({framework}) g\u00e9n\u00e9r\u00e9 — "
            f"Score global : {overall_score:.0f}/100 — "
            f"{total_findings} findings ({critical_count} critiques, "
            f"{high_count} \u00e9lev\u00e9s, {medium_count} moyens, {low_count} faibles)"
        )

        return SkillOutput(
            success=True,
            pdf_path=saved_path,
            html_content=html_content,
            report_data=report_data,
            summary=summary,
        )

    except Exception as e:
        return SkillOutput(success=False, error=str(e))
