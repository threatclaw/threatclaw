"""
skill-shadow-ai-monitor -- détection et qualification Shadow AI.

Consomme les alertes Sigma shadow-ai-001..004 (migration V40), les enrichit
contre la table llm_endpoint_feed et la policy threatclaw.toml [shadow_ai],
puis produit des findings AI_USAGE_POLICY pour auditabilité EU AI Act / NIS2.

Squelette v0.1 — la logique d'insertion DB réelle est à câbler via le
connector db.* utilisé par les autres skills Python (voir skill-soc-monitor).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class PolicyDecision(Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    UNREVIEWED = "unreviewed"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class LlmEndpoint:
    """Row from llm_endpoint_feed."""
    detection_type: str   # fqdn | port | url_pattern
    value: str
    provider: Optional[str]
    category: str         # commercial | self-hosted | coding-assistant | hub | hyperscaler
    tier: int
    tags: list[str] = field(default_factory=list)


@dataclass
class ShadowAiPolicy:
    """Loaded from threatclaw.toml [shadow_ai] section."""
    enabled: bool = True
    default_decision: PolicyDecision = PolicyDecision.UNREVIEWED
    allowed_providers: set[str] = field(default_factory=set)
    denied_providers: set[str] = field(default_factory=set)
    denied_categories: set[str] = field(default_factory=set)
    severity_allowed: Severity = Severity.INFORMATIONAL
    severity_unreviewed: Severity = Severity.MEDIUM
    severity_denied: Severity = Severity.HIGH
    severity_self_hosted: Severity = Severity.HIGH

    @classmethod
    def from_toml(cls, section: dict[str, Any]) -> "ShadowAiPolicy":
        def _sev(key: str, default: Severity) -> Severity:
            raw = section.get(key)
            return Severity(raw) if raw else default

        return cls(
            enabled=section.get("enabled", True),
            default_decision=PolicyDecision(section.get("default_decision", "unreviewed")),
            allowed_providers={p.lower() for p in section.get("allowed_providers", [])},
            denied_providers={p.lower() for p in section.get("denied_providers", [])},
            denied_categories={c.lower() for c in section.get("denied_categories", [])},
            severity_allowed=_sev("severity_allowed", Severity.INFORMATIONAL),
            severity_unreviewed=_sev("severity_unreviewed", Severity.MEDIUM),
            severity_denied=_sev("severity_denied", Severity.HIGH),
            severity_self_hosted=_sev("severity_self_hosted", Severity.HIGH),
        )


@dataclass
class ShadowAiFinding:
    """Output record inserted into findings table."""
    asset: str
    user: Optional[str]
    severity: Severity
    endpoint: LlmEndpoint
    policy_decision: PolicyDecision
    policy_reason: str
    first_seen_ts: datetime
    last_seen_ts: datetime
    connection_count: int
    bytes_total: int
    regulatory_flags: list[str]

    def to_finding_record(self) -> dict[str, Any]:
        """Shape compatible with FindingRecord for db.insert_finding()."""
        return {
            "skill_id": "shadow-ai-monitor",
            "title": self._title(),
            "description": self.policy_reason,
            "severity": self.severity.value,
            "category": "AI_USAGE_POLICY",
            "asset": self.asset,
            "source": "zeek",
            "metadata": {
                "llm_provider": self.endpoint.provider,
                "llm_category": self.endpoint.category,
                "llm_tier": self.endpoint.tier,
                "detection_type": self.endpoint.detection_type,
                "endpoint": self.endpoint.value,
                "user": self.user,
                "policy_decision": self.policy_decision.value,
                "policy_reason": self.policy_reason,
                "first_seen_ts": self.first_seen_ts.isoformat(),
                "last_seen_ts": self.last_seen_ts.isoformat(),
                "connection_count": self.connection_count,
                "bytes_total": self.bytes_total,
                "regulatory_flags": self.regulatory_flags,
            },
        }

    def _title(self) -> str:
        prov = self.endpoint.provider or "unknown LLM"
        return f"Shadow AI — {prov} via {self.endpoint.value} ({self.policy_decision.value})"


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------

REGULATORY_FLAGS_BASE = ["eu_ai_act_art12", "nis2_art21_2d", "iso_42001_a10"]


def evaluate_policy(endpoint: LlmEndpoint, policy: ShadowAiPolicy) -> tuple[PolicyDecision, str, Severity]:
    """Decide allowed/denied/unreviewed + severity for one endpoint hit."""
    provider_lc = (endpoint.provider or "").lower()
    category_lc = endpoint.category.lower()

    if provider_lc in policy.denied_providers:
        return (
            PolicyDecision.DENIED,
            f"provider '{endpoint.provider}' is in denied_providers",
            policy.severity_denied,
        )

    if category_lc in policy.denied_categories:
        return (
            PolicyDecision.DENIED,
            f"category '{endpoint.category}' is in denied_categories",
            policy.severity_denied,
        )

    if provider_lc in policy.allowed_providers:
        return (
            PolicyDecision.ALLOWED,
            f"provider '{endpoint.provider}' is in allowed_providers",
            policy.severity_allowed,
        )

    if category_lc == "self-hosted":
        return (
            PolicyDecision.UNREVIEWED,
            "undeclared self-hosted LLM runtime detected on LAN",
            policy.severity_self_hosted,
        )

    return (
        policy.default_decision,
        "no explicit policy entry — defaulted",
        policy.severity_unreviewed,
    )


# ---------------------------------------------------------------------------
# Main orchestration (stub — wiring to db.* to be completed in v0.2)
# ---------------------------------------------------------------------------

async def qualify_shadow_ai_alerts(
    db,                                # db connector (see skill-soc-monitor convention)
    policy: ShadowAiPolicy,
    time_range: timedelta = timedelta(hours=24),
    alert_ids: Optional[list[int]] = None,
) -> dict[str, Any]:
    """Main entry point for the skill.

    Steps:
      1. Fetch sigma_alerts where rule_id LIKE 'shadow-ai-%' within time_range.
      2. For each alert, parse the underlying log (ssl/dns/conn/http).
      3. Lookup llm_endpoint_feed by value/port/pattern → LlmEndpoint.
      4. Resolve user identity via kerberos.log (±5min window around alert).
      5. Evaluate policy → (decision, reason, severity).
      6. Aggregate per (asset, endpoint) over the window to dedupe.
      7. Emit one ShadowAiFinding per aggregate.
    """
    if not policy.enabled:
        log.info("shadow-ai-monitor disabled by policy")
        return {"alerts_processed": 0, "findings_created": 0}

    # TODO v0.2 — real DB wiring. Interface expected (matches skill-soc-monitor):
    #   alerts = await db.list_sigma_alerts(since=..., rule_id_prefix='shadow-ai-')
    #   for alert in alerts:
    #       raw_log = await db.get_log_by_id(alert.log_id)
    #       endpoint = await _lookup_endpoint(db, raw_log, alert.rule_id)
    #       user = await _resolve_user(db, raw_log.source_ip, alert.detected_at)
    #       decision, reason, severity = evaluate_policy(endpoint, policy)
    #       finding = ShadowAiFinding(...)
    #       await db.insert_finding(finding.to_finding_record())

    raise NotImplementedError(
        "DB wiring pending — see skill-soc-monitor/src/main.py for the async db.* "
        "interface to reuse."
    )


async def _lookup_endpoint(db, raw_log: dict, rule_id: str) -> Optional[LlmEndpoint]:
    """Resolve a log hit against llm_endpoint_feed.

    Dispatches on rule_id:
      shadow-ai-001 → ssl.log:server_name → fqdn lookup (contains match)
      shadow-ai-002 → dns.log:query       → fqdn lookup (contains match)
      shadow-ai-003 → conn.log:id.resp_p  → port lookup
      shadow-ai-004 → http.log:uri        → url_pattern lookup (contains match)
    """
    raise NotImplementedError  # stub


async def _resolve_user(db, source_ip: str, detected_at: datetime) -> Optional[str]:
    """Find Kerberos-authenticated user for source_ip at detected_at ±5min."""
    raise NotImplementedError  # stub


# ---------------------------------------------------------------------------
# CLI harness (dev convenience — matches skill-soc-monitor pattern)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Smoke test the policy engine with a fake endpoint
    policy = ShadowAiPolicy(
        enabled=True,
        default_decision=PolicyDecision.UNREVIEWED,
        allowed_providers={"mistral"},
        denied_providers={"deepseek"},
        denied_categories={"coding-assistant"},
    )

    samples = [
        LlmEndpoint("fqdn", "api.openai.com",   "OpenAI",     "commercial",       1),
        LlmEndpoint("fqdn", "api.mistral.ai",   "Mistral",    "commercial",       1),
        LlmEndpoint("fqdn", "chat.deepseek.com","DeepSeek",   "commercial",       2),
        LlmEndpoint("fqdn", "api.cursor.sh",    "Cursor",     "coding-assistant", 7),
        LlmEndpoint("port", "11434",            "Ollama",     "self-hosted",      6),
    ]

    print("Policy smoke test:")
    for s in samples:
        decision, reason, severity = evaluate_policy(s, policy)
        print(f"  {s.provider:10s} ({s.category:17s}) → {decision.value:11s}  {severity.value:13s}  {reason}")
