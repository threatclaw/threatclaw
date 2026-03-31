"""Company Context — adjusts ML scores based on company profile.

Uses the company_profile table to modify anomaly thresholds:
- Business hours: activity outside hours gets a score multiplier
- Geo scope: connections from blocked countries boost score
- Sector: adjusts sensitivity
- Company size: affects baseline expectations
"""

import logging
from datetime import datetime
from . import db

logger = logging.getLogger("ml.context")


def get_context_multipliers():
    """Load company profile and compute context-aware multipliers."""
    profile = db.get_company_profile()
    if not profile:
        return {"hour_mult": 1.0, "geo_mult": 1.0, "sector_mult": 1.0}

    # Business hours multiplier
    hours = profile.get("business_hours", "office")
    if hours == "24x7":
        hour_mult = 1.0  # No hour-based adjustment
    elif hours == "shifts":
        hour_mult = 1.3  # Slight boost outside shift patterns
    else:
        # Office hours (8h-18h) — night/weekend activity is 2x more suspicious
        hour_mult = 2.0

    # Sector sensitivity
    sector = profile.get("sector", "other")
    sector_multipliers = {
        "healthcare": 1.5,    # More sensitive (patient data, IoMT)
        "finance": 1.4,       # More sensitive (transactions, PCI-DSS)
        "government": 1.3,    # More sensitive (citizen data)
        "energy": 1.4,        # Critical infrastructure (SCADA)
        "industry": 1.2,      # OT concerns
        "retail": 1.1,        # POS, e-commerce
        "services": 1.0,      # Default
        "education": 1.0,
        "transport": 1.2,     # Fleet, logistics
        "other": 1.0,
    }
    sector_mult = sector_multipliers.get(sector, 1.0)

    # Geo scope
    geo_scope = profile.get("geo_scope", "france")
    if geo_scope == "france":
        geo_mult = 2.0  # Connections outside France are very suspicious
    elif geo_scope == "europe":
        geo_mult = 1.5  # Outside Europe is suspicious
    else:
        geo_mult = 1.0  # International — hard to filter by geo

    # Anomaly sensitivity from profile
    sensitivity = profile.get("anomaly_sensitivity", "medium")
    if sensitivity == "high":
        base_mult = 1.3
    elif sensitivity == "low":
        base_mult = 0.7
    else:
        base_mult = 1.0

    return {
        "hour_mult": hour_mult,
        "geo_mult": geo_mult,
        "sector_mult": sector_mult * base_mult,
        "business_hours_start": profile.get("business_hours_start", "08:00"),
        "business_hours_end": profile.get("business_hours_end", "18:00"),
        "work_days": profile.get("work_days", ["mon", "tue", "wed", "thu", "fri"]),
        "blocked_countries": profile.get("blocked_countries", []),
    }


def adjust_score(raw_score, asset_features, context=None):
    """Adjust a raw anomaly score (0-1) using company context.

    Returns adjusted score (still 0-1) and reason.
    """
    if context is None:
        context = get_context_multipliers()

    adjusted = raw_score
    reasons = []

    # Time-based adjustment
    night_ratio = asset_features.get("night_ratio", 0)
    weekend_ratio = asset_features.get("weekend_ratio", 0)

    if night_ratio > 0.5 and context["hour_mult"] > 1.0:
        boost = (night_ratio - 0.5) * 0.3 * context["hour_mult"]
        adjusted += boost
        reasons.append(f"Night activity ({night_ratio:.0%}) outside business hours")

    if weekend_ratio > 0.3 and "sat" not in context.get("work_days", []):
        boost = weekend_ratio * 0.2 * context["hour_mult"]
        adjusted += boost
        reasons.append(f"Weekend activity ({weekend_ratio:.0%}) outside work days")

    # Sector multiplier
    if context["sector_mult"] != 1.0:
        adjusted *= context["sector_mult"]

    # Cap at 1.0
    adjusted = min(1.0, max(0.0, adjusted))

    reason = "; ".join(reasons) if reasons else "No context adjustment"

    return round(adjusted, 3), reason
