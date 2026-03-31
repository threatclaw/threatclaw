"""ThreatClaw SDK — Python client for skills to interact with the Core API."""

from .client import ThreatClawClient
from .models import Finding, Alert, SkillConfig, Severity

__version__ = "0.1.0"
__all__ = ["ThreatClawClient", "Finding", "Alert", "SkillConfig", "Severity"]
