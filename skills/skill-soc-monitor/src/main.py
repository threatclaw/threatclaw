"""
skill-soc-monitor — SOC monitoring & alert triage
Fluent Bit logs + Sigma rules + LLM triage
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Alert:
    rule_name: str
    severity: AlertSeverity
    source: str
    timestamp: str
    description: str
    sigma_rule_id: str = ""
    is_false_positive: bool = False
    triage_notes: str = ""
    mitre_attack_id: str = ""


@dataclass
class SkillInput:
    time_range: str = "24h"
    sources: list[str] = field(default_factory=list)
    sigma_rulesets: list[str] = field(default_factory=lambda: ["core"])


@dataclass
class SkillOutput:
    success: bool = False
    alerts: list[Alert] = field(default_factory=list)
    false_positive_rate: float = 0.0
    summary: str = ""
    error: Optional[str] = None


async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    try:
        # TODO: Query Fluent Bit / PostgreSQL for logs
        # TODO: Apply Sigma rules
        # TODO: LLM triage for false positive detection
        return SkillOutput(success=True, summary="Analyse SOC terminée")
    except Exception as e:
        return SkillOutput(success=False, error=str(e))
