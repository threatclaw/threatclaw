"""
skill-soc-monitor -- SOC monitoring & alert triage
Fluent Bit logs + Sigma rules + LLM triage

Collects logs from PostgreSQL, applies Sigma detection rules, correlates
alerts across multiple dimensions, and performs heuristic-based triage
(with a placeholder for future LLM-driven analysis).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from src.sigma_engine import MatchResult, SigmaRule, match_log, load_rules_from_directory


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

_SIGMA_LEVEL_TO_SEVERITY: dict[str, AlertSeverity] = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "informational": AlertSeverity.INFORMATIONAL,
}

# Time-range string to timedelta conversion
_TIME_RANGE_RE = re.compile(r"^(\d+)\s*(h|d|m|s)$", re.IGNORECASE)

_TIME_RANGE_PRESETS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}


def parse_time_range(tr: str) -> timedelta:
    """Convert a human time-range string like ``'1h'`` or ``'7d'`` to a
    :class:`~datetime.timedelta`.

    Recognised formats: ``<int>h``, ``<int>d``, ``<int>m``, ``<int>s`` and
    the preset strings ``1h``, ``6h``, ``24h``, ``7d``.

    Raises :exc:`ValueError` for unrecognised input.
    """
    key = tr.strip().lower()
    if key in _TIME_RANGE_PRESETS:
        return _TIME_RANGE_PRESETS[key]

    m = _TIME_RANGE_RE.match(key)
    if m:
        amount = int(m.group(1))
        unit = m.group(2).lower()
        if unit == "h":
            return timedelta(hours=amount)
        if unit == "d":
            return timedelta(days=amount)
        if unit == "m":
            return timedelta(minutes=amount)
        if unit == "s":
            return timedelta(seconds=amount)

    raise ValueError(f"Unrecognised time_range: {tr!r}")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    rule_name: str
    severity: AlertSeverity
    source: str
    timestamp: str
    description: str
    sigma_rule_id: str = ""
    matched_fields: dict[str, Any] = field(default_factory=dict)
    hostname: str = ""
    source_ip: str = ""
    username: str = ""
    mitre_tags: list[str] = field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    triage_notes: str = ""
    correlation_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly dictionary representation."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class Correlation:
    correlation_id: str
    alerts: list[Alert]
    pattern: str
    confidence: float  # 0.0 -- 1.0
    description: str


@dataclass
class TriageResult:
    alert: Alert
    is_false_positive: bool
    confidence: float  # 0.0 -- 1.0
    reasoning: str


@dataclass
class SkillInput:
    time_range: str = "24h"
    sources: list[str] = field(default_factory=list)
    sigma_rulesets: list[str] = field(default_factory=lambda: ["core"])
    auto_triage: bool = False


@dataclass
class SkillOutput:
    success: bool = False
    alerts: list[Alert] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    false_positive_rate: float = 0.0
    total_logs_analyzed: int = 0
    rules_matched: int = 0
    summary: str = ""
    error: Optional[str] = None


@dataclass
class ScanStats:
    total_logs: int = 0
    matched_logs: int = 0
    rules_loaded: int = 0
    rules_matched: int = 0
    scan_duration: float = 0.0


# ---------------------------------------------------------------------------
# Known-safe / heuristic constants for triage
# ---------------------------------------------------------------------------

KNOWN_SAFE_IPS: set[str] = {
    "127.0.0.1",
    "::1",
    "10.0.0.1",
    "192.168.1.1",
}

_DEV_HOSTNAME_RE = re.compile(r"(test|dev|staging|sandbox|local)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Log collection from PostgreSQL (via docker exec)
# ---------------------------------------------------------------------------

async def fetch_logs_from_db(
    time_range: str,
    sources: list[str],
) -> list[dict]:
    """Fetch log records from the ``logs`` table in PostgreSQL.

    The database is accessed by running ``psql`` inside the
    ``threatclaw-db`` Docker container.

    Parameters
    ----------
    time_range:
        Human-readable interval such as ``"1h"`` or ``"7d"``.
    sources:
        Optional list of log source tags to filter on (column ``tag``).

    Returns
    -------
    list[dict]
        Each element is a log record represented as a dictionary.
    """
    delta = parse_time_range(time_range)
    # Convert timedelta to PostgreSQL interval notation.
    total_seconds = int(delta.total_seconds())
    interval = f"{total_seconds} seconds"

    where_clauses = [f"timestamp >= NOW() - INTERVAL '{interval}'"]
    if sources:
        escaped = ", ".join(f"'{s}'" for s in sources)
        where_clauses.append(f"tag IN ({escaped})")

    where_sql = " AND ".join(where_clauses)
    query = f"SELECT row_to_json(t) FROM (SELECT * FROM logs WHERE {where_sql} ORDER BY timestamp DESC) t;"

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


# ---------------------------------------------------------------------------
# Sigma rule application
# ---------------------------------------------------------------------------

def apply_sigma_rules(logs: list[dict], rules: list[SigmaRule]) -> list[Alert]:
    """Evaluate every log record against every Sigma rule.

    Returns a list of :class:`Alert` objects for each match.
    """
    alerts: list[Alert] = []

    for log in logs:
        results: list[MatchResult] = match_log(log, rules)
        for mr in results:
            severity = _SIGMA_LEVEL_TO_SEVERITY.get(
                mr.level.lower(), AlertSeverity.MEDIUM,
            )

            hostname = str(
                log.get("hostname")
                or log.get("Hostname")
                or log.get("host")
                or log.get("ComputerName")
                or ""
            )
            source_ip = str(
                log.get("source_ip")
                or log.get("SourceIP")
                or log.get("src_ip")
                or log.get("IpAddress")
                or ""
            )
            username = str(
                log.get("username")
                or log.get("User")
                or log.get("TargetUserName")
                or log.get("SubjectUserName")
                or ""
            )

            # Derive source tag from log metadata.
            source = str(log.get("tag") or log.get("source") or "unknown")

            ts = str(
                log.get("timestamp")
                or log.get("@timestamp")
                or datetime.now(timezone.utc).isoformat()
            )

            alert = Alert(
                rule_name=mr.title,
                severity=severity,
                source=source,
                timestamp=ts,
                description=f"Sigma rule matched: {mr.title}",
                sigma_rule_id=mr.rule_id,
                matched_fields=dict(mr.matched_fields),
                hostname=hostname,
                source_ip=source_ip,
                username=username,
                mitre_tags=list(mr.tags),
            )
            alerts.append(alert)

    return alerts


# ---------------------------------------------------------------------------
# Alert correlation
# ---------------------------------------------------------------------------

def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Best-effort ISO timestamp parsing, returning ``None`` on failure."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _within_window(a: Alert, b: Alert, window: timedelta) -> bool:
    """Return ``True`` if both alerts are within *window* of each other."""
    ta = _parse_ts(a.timestamp)
    tb = _parse_ts(b.timestamp)
    if ta is None or tb is None:
        return False
    return abs(ta - tb) <= window


def correlate_alerts(alerts: list[Alert]) -> list[Correlation]:
    """Correlate alerts across multiple dimensions.

    Strategies
    ----------
    1. **Same source IP** within 5 minutes -- "Multi-alert from same source"
    2. **Same username** within 5 minutes -- "Repeated auth events for same user"
    3. **Same hostname** within 5 minutes -- "Host under attack"
    4. **Brute force**: 5+ failed-auth alerts from the same source within 10 min
    5. **Lateral movement**: same user seen from different IPs
    """
    correlations: list[Correlation] = []
    seen_ids: set[str] = set()
    five_min = timedelta(minutes=5)
    ten_min = timedelta(minutes=10)

    # --- 1. Group by source_ip (non-empty) within 5-min window ---
    ip_groups: dict[str, list[Alert]] = {}
    for a in alerts:
        if a.source_ip:
            ip_groups.setdefault(a.source_ip, []).append(a)

    for ip, group in ip_groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda a: a.timestamp)
        cluster: list[Alert] = [group[0]]
        for a in group[1:]:
            if _within_window(cluster[0], a, five_min):
                cluster.append(a)
            else:
                if len(cluster) >= 2:
                    cid = str(uuid.uuid4())
                    correlations.append(Correlation(
                        correlation_id=cid,
                        alerts=list(cluster),
                        pattern="same_source_ip",
                        confidence=min(0.5 + 0.1 * len(cluster), 1.0),
                        description=f"Multi-alert from same source {ip}",
                    ))
                    seen_ids.add(cid)
                cluster = [a]
        if len(cluster) >= 2:
            cid = str(uuid.uuid4())
            correlations.append(Correlation(
                correlation_id=cid,
                alerts=list(cluster),
                pattern="same_source_ip",
                confidence=min(0.5 + 0.1 * len(cluster), 1.0),
                description=f"Multi-alert from same source {ip}",
            ))
            seen_ids.add(cid)

    # --- 2. Group by username within 5-min window ---
    user_groups: dict[str, list[Alert]] = {}
    for a in alerts:
        if a.username:
            user_groups.setdefault(a.username, []).append(a)

    for user, group in user_groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda a: a.timestamp)
        cluster: list[Alert] = [group[0]]
        for a in group[1:]:
            if _within_window(cluster[0], a, five_min):
                cluster.append(a)
            else:
                if len(cluster) >= 2:
                    cid = str(uuid.uuid4())
                    correlations.append(Correlation(
                        correlation_id=cid,
                        alerts=list(cluster),
                        pattern="same_username",
                        confidence=min(0.4 + 0.1 * len(cluster), 1.0),
                        description=f"Repeated auth events for same user {user}",
                    ))
                cluster = [a]
        if len(cluster) >= 2:
            cid = str(uuid.uuid4())
            correlations.append(Correlation(
                correlation_id=cid,
                alerts=list(cluster),
                pattern="same_username",
                confidence=min(0.4 + 0.1 * len(cluster), 1.0),
                description=f"Repeated auth events for same user {user}",
            ))

    # --- 3. Group by hostname within 5-min window ---
    host_groups: dict[str, list[Alert]] = {}
    for a in alerts:
        if a.hostname:
            host_groups.setdefault(a.hostname, []).append(a)

    for host, group in host_groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda a: a.timestamp)
        cluster: list[Alert] = [group[0]]
        for a in group[1:]:
            if _within_window(cluster[0], a, five_min):
                cluster.append(a)
            else:
                if len(cluster) >= 2:
                    cid = str(uuid.uuid4())
                    correlations.append(Correlation(
                        correlation_id=cid,
                        alerts=list(cluster),
                        pattern="same_hostname",
                        confidence=min(0.4 + 0.1 * len(cluster), 1.0),
                        description=f"Host under attack: {host}",
                    ))
                cluster = [a]
        if len(cluster) >= 2:
            cid = str(uuid.uuid4())
            correlations.append(Correlation(
                correlation_id=cid,
                alerts=list(cluster),
                pattern="same_hostname",
                confidence=min(0.4 + 0.1 * len(cluster), 1.0),
                description=f"Host under attack: {host}",
            ))

    # --- 4. Brute force: 5+ failed-auth alerts from same IP in 10 min ---
    _BRUTE_KEYWORDS = {"brute", "failed", "logon", "authentication", "login"}
    auth_by_ip: dict[str, list[Alert]] = {}
    for a in alerts:
        if not a.source_ip:
            continue
        lower_desc = (a.rule_name + " " + a.description).lower()
        if any(kw in lower_desc for kw in _BRUTE_KEYWORDS):
            auth_by_ip.setdefault(a.source_ip, []).append(a)

    for ip, group in auth_by_ip.items():
        if len(group) < 5:
            continue
        group.sort(key=lambda a: a.timestamp)
        cluster: list[Alert] = [group[0]]
        for a in group[1:]:
            if _within_window(cluster[0], a, ten_min):
                cluster.append(a)
            else:
                if len(cluster) >= 5:
                    cid = str(uuid.uuid4())
                    correlations.append(Correlation(
                        correlation_id=cid,
                        alerts=list(cluster),
                        pattern="brute_force",
                        confidence=min(0.7 + 0.05 * len(cluster), 1.0),
                        description=f"Brute force detected from {ip}: {len(cluster)} failed auth attempts",
                    ))
                cluster = [a]
        if len(cluster) >= 5:
            cid = str(uuid.uuid4())
            correlations.append(Correlation(
                correlation_id=cid,
                alerts=list(cluster),
                pattern="brute_force",
                confidence=min(0.7 + 0.05 * len(cluster), 1.0),
                description=f"Brute force detected from {ip}: {len(cluster)} failed auth attempts",
            ))

    # --- 5. Lateral movement: same user from different IPs ---
    for user, group in user_groups.items():
        distinct_ips = {a.source_ip for a in group if a.source_ip}
        if len(distinct_ips) >= 2:
            cid = str(uuid.uuid4())
            correlations.append(Correlation(
                correlation_id=cid,
                alerts=list(group),
                pattern="lateral_movement",
                confidence=min(0.6 + 0.1 * len(distinct_ips), 1.0),
                description=(
                    f"Lateral movement: user {user} seen from "
                    f"{len(distinct_ips)} different IPs"
                ),
            ))

    return correlations


# ---------------------------------------------------------------------------
# LLM-based triage (heuristic stub)
# ---------------------------------------------------------------------------

def triage_alert(alert: Alert) -> TriageResult:
    """Triage a single alert using heuristic rules.

    TODO: Replace heuristic fallback with an actual LLM call for richer
    reasoning once the inference service is integrated.

    Heuristics
    ----------
    * Known safe IPs -> likely false positive (confidence 0.9)
    * Test / dev hostnames -> lower severity, moderate FP confidence (0.7)
    * Night-time authentication failures (00:00-06:00 UTC) -> higher suspicion
    * Informational severity -> likely false positive (0.8)
    """
    is_fp = False
    confidence = 0.5
    reasons: list[str] = []

    # 1. Known safe IPs
    if alert.source_ip in KNOWN_SAFE_IPS:
        is_fp = True
        confidence = 0.9
        reasons.append(f"Source IP {alert.source_ip} is in the known-safe list")

    # 2. Test / dev hostname
    if alert.hostname and _DEV_HOSTNAME_RE.search(alert.hostname):
        is_fp = True
        confidence = max(confidence, 0.7)
        reasons.append(f"Hostname '{alert.hostname}' appears to be a test/dev system")

    # 3. Informational severity
    if alert.severity == AlertSeverity.INFORMATIONAL:
        is_fp = True
        confidence = max(confidence, 0.8)
        reasons.append("Alert severity is informational")

    # 4. Night-time auth failure -> higher suspicion (NOT false positive)
    ts = _parse_ts(alert.timestamp)
    if ts is not None and 0 <= ts.hour < 6:
        lower_desc = (alert.rule_name + " " + alert.description).lower()
        auth_keywords = {"auth", "login", "logon", "password", "credential"}
        if any(kw in lower_desc for kw in auth_keywords):
            is_fp = False
            confidence = 0.85
            reasons.append("Night-time authentication event (00:00-06:00 UTC) -- higher suspicion")

    if not reasons:
        reasons.append("No specific heuristic matched; default assessment")

    return TriageResult(
        alert=alert,
        is_false_positive=is_fp,
        confidence=confidence,
        reasoning="; ".join(reasons),
    )


# ---------------------------------------------------------------------------
# Statistics helper
# ---------------------------------------------------------------------------

def compute_scan_stats(
    total_logs: int,
    alerts: list[Alert],
    rules_loaded: int,
    duration: float,
) -> ScanStats:
    """Build a :class:`ScanStats` summary."""
    unique_rules = {a.sigma_rule_id for a in alerts if a.sigma_rule_id}
    return ScanStats(
        total_logs=total_logs,
        matched_logs=len(alerts),
        rules_loaded=rules_loaded,
        rules_matched=len(unique_rules),
        scan_duration=duration,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run(skill_input: SkillInput) -> SkillOutput:
    """Main skill entry point.

    Pipeline: Fetch logs -> Apply Sigma rules -> Correlate -> Triage -> Summary
    """
    t0 = time.monotonic()

    try:
        # 1. Fetch logs from PostgreSQL
        logs = await fetch_logs_from_db(skill_input.time_range, skill_input.sources)

        # 2. Load Sigma rules from configured rulesets
        rules: list[SigmaRule] = []
        for ruleset in skill_input.sigma_rulesets:
            ruleset_path = f"/etc/threatclaw/sigma/{ruleset}"
            try:
                rules.extend(load_rules_from_directory(ruleset_path))
            except FileNotFoundError:
                pass  # ruleset directory may not exist yet

        # 3. Apply Sigma rules
        alerts = apply_sigma_rules(logs, rules)

        # 4. Correlate alerts
        correlations = correlate_alerts(alerts)

        # 5. Optional triage
        fp_count = 0
        if skill_input.auto_triage and alerts:
            triaged: list[Alert] = []
            for alert in alerts:
                result = triage_alert(alert)
                alert.triage_notes = result.reasoning
                if result.is_false_positive:
                    alert.status = AlertStatus.FALSE_POSITIVE
                    fp_count += 1
                triaged.append(alert)
            alerts = triaged

        # 6. Compute statistics
        duration = time.monotonic() - t0
        stats = compute_scan_stats(len(logs), alerts, len(rules), duration)

        false_positive_rate = (fp_count / len(alerts)) if alerts else 0.0

        # 7. Build summary
        severity_counts: dict[str, int] = {}
        for a in alerts:
            sev = a.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary_parts = [
            f"Scanned {stats.total_logs} logs in {stats.scan_duration:.2f}s.",
            f"Matched {stats.matched_logs} alerts from {stats.rules_matched} rules.",
        ]
        if severity_counts:
            sev_str = ", ".join(f"{k}: {v}" for k, v in severity_counts.items())
            summary_parts.append(f"Severity breakdown: {sev_str}.")
        if correlations:
            summary_parts.append(f"Found {len(correlations)} correlation(s).")
        if skill_input.auto_triage:
            summary_parts.append(f"False positive rate: {false_positive_rate:.1%}.")

        summary = " ".join(summary_parts)

        return SkillOutput(
            success=True,
            alerts=alerts,
            correlations=correlations,
            false_positive_rate=false_positive_rate,
            total_logs_analyzed=stats.total_logs,
            rules_matched=stats.rules_matched,
            summary=summary,
        )

    except Exception as e:
        return SkillOutput(success=False, error=str(e))
