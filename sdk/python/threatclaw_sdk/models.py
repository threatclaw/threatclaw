"""Data models for ThreatClaw SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Finding:
    """A security finding produced by a skill."""
    skill_id: str
    title: str
    severity: str = Severity.INFO
    description: Optional[str] = None
    category: Optional[str] = None
    asset: Optional[str] = None
    source: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict:
        d = {"skill_id": self.skill_id, "title": self.title, "severity": self.severity}
        if self.description:
            d["description"] = self.description
        if self.category:
            d["category"] = self.category
        if self.asset:
            d["asset"] = self.asset
        if self.source:
            d["source"] = self.source
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class Alert:
    """A SOC alert."""
    id: int
    rule_id: str
    level: str
    title: str
    status: str
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    matched_at: Optional[str] = None


@dataclass
class SkillConfig:
    """Configuration for a skill."""
    skill_id: str
    settings: dict[str, str] = field(default_factory=dict)
