"""Feature extraction from PostgreSQL data for ML models."""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from . import db


def extract_asset_features(hours_back=24):
    """Extract per-asset behavioral features from alerts + logs.

    Returns a dict: { asset_id: { feature_name: value, ... } }

    Features per asset (per time window):
    - alerts_count: number of sigma alerts
    - alerts_critical: number of critical alerts
    - alerts_high: number of high alerts
    - unique_source_ips: distinct source IPs in alerts
    - unique_rules: distinct sigma rules triggered
    - logs_count: number of log entries
    - auth_failures: SSH/auth failures in logs
    - auth_successes: SSH/auth successes in logs
    - dns_queries: DNS query count
    - unique_destinations: unique destination IPs/hostnames
    - hour_entropy: spread of activity across hours (0=single hour, 1=uniform)
    - weekend_ratio: fraction of events on weekend
    - night_ratio: fraction of events outside 8h-18h
    """
    alerts = db.get_alerts(hours_back=hours_back)
    logs = db.get_logs(hours_back=hours_back)
    assets = db.get_assets()

    # Build IP → asset mapping
    ip_to_asset = {}
    for a in assets:
        for ip in (a.get("ip_addresses") or []):
            ip_to_asset[ip] = a["id"]
        if a.get("hostname"):
            ip_to_asset[a["hostname"]] = a["id"]

    features = defaultdict(lambda: {
        "alerts_count": 0, "alerts_critical": 0, "alerts_high": 0,
        "unique_source_ips": set(), "unique_rules": set(),
        "logs_count": 0, "auth_failures": 0, "auth_successes": 0,
        "dns_queries": 0, "unique_destinations": set(),
        "hours": [], "is_weekend": [], "is_night": [],
    })

    # Process alerts
    for a in alerts:
        hostname = a.get("hostname") or ""
        asset_id = ip_to_asset.get(hostname, hostname)
        if not asset_id:
            continue

        f = features[asset_id]
        f["alerts_count"] += 1
        level = (a.get("level") or "").lower()
        if level == "critical":
            f["alerts_critical"] += 1
        elif level == "high":
            f["alerts_high"] += 1

        src_ip = a.get("source_ip", "")
        if src_ip:
            clean_ip = src_ip.split("/")[0] if "/" in src_ip else src_ip
            f["unique_source_ips"].add(clean_ip)

        f["unique_rules"].add(a.get("rule_id", ""))

        ts = a.get("matched_at")
        if ts:
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except:
                    ts = None
            if ts:
                f["hours"].append(ts.hour)
                f["is_weekend"].append(1 if ts.weekday() >= 5 else 0)
                f["is_night"].append(1 if ts.hour < 8 or ts.hour >= 18 else 0)

    # Process logs
    for log in logs:
        hostname = log.get("hostname") or ""
        asset_id = ip_to_asset.get(hostname, hostname)
        if not asset_id:
            continue

        f = features[asset_id]
        f["logs_count"] += 1

        data = log.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}

        msg = data.get("message", "")
        if "Failed password" in msg or "authentication failure" in msg:
            f["auth_failures"] += 1
        elif "Accepted password" in msg or "Accepted publickey" in msg:
            f["auth_successes"] += 1

        if "query:" in msg or "dns_query" in data:
            f["dns_queries"] += 1

        src_ip = data.get("source_ip", "")
        if src_ip:
            f["unique_destinations"].add(src_ip)

    # Convert to numeric features
    result = {}
    for asset_id, f in features.items():
        hours = f["hours"]
        hour_entropy = _compute_entropy(hours, 24) if hours else 0.0
        weekend_events = f["is_weekend"]
        night_events = f["is_night"]

        result[asset_id] = {
            "alerts_count": f["alerts_count"],
            "alerts_critical": f["alerts_critical"],
            "alerts_high": f["alerts_high"],
            "unique_source_ips": len(f["unique_source_ips"]),
            "unique_rules": len(f["unique_rules"]),
            "logs_count": f["logs_count"],
            "auth_failures": f["auth_failures"],
            "auth_successes": f["auth_successes"],
            "dns_queries": f["dns_queries"],
            "unique_destinations": len(f["unique_destinations"]),
            "hour_entropy": round(hour_entropy, 3),
            "weekend_ratio": round(sum(weekend_events) / max(len(weekend_events), 1), 3),
            "night_ratio": round(sum(night_events) / max(len(night_events), 1), 3),
        }

    return result


def extract_dns_features():
    """Extract features from DNS queries for DGA detection.

    Returns a list of { domain, features } dicts.
    """
    import math
    dns_logs = db.get_dns_queries(hours_back=24)
    domains = set()

    for log in dns_logs:
        data = log.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}

        msg = data.get("message", "")
        # Extract domain from "query: xk3j9f2m.evil.com IN A +"
        if "query:" in msg:
            parts = msg.split("query:")[1].strip().split()
            if parts:
                domain = parts[0].strip().rstrip(".")
                domains.add(domain)

        # Or from structured data
        dns_query = data.get("dns_query", "")
        if dns_query:
            domains.add(dns_query.strip().rstrip("."))

    result = []
    for domain in domains:
        feats = _compute_domain_features(domain)
        if feats:
            result.append({"domain": domain, "features": feats})

    return result


def _compute_domain_features(domain):
    """Compute features for DGA detection on a domain name."""
    import math
    import string

    # Only analyze the effective second-level domain
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    sld = parts[-2]  # second-level domain (e.g., "evil" from "xk3j9.evil.com")

    if len(sld) < 3:
        return None

    # Features
    length = len(sld)

    # Character entropy
    freq = defaultdict(int)
    for c in sld:
        freq[c] += 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())

    # Consonant ratio
    vowels = set("aeiou")
    consonants = sum(1 for c in sld.lower() if c in string.ascii_lowercase and c not in vowels)
    consonant_ratio = consonants / max(length, 1)

    # Digit ratio
    digits = sum(1 for c in sld if c.isdigit())
    digit_ratio = digits / max(length, 1)

    # Unique char ratio
    unique_ratio = len(set(sld)) / max(length, 1)

    # Has hyphens
    hyphen_count = sld.count("-")

    # Bigram frequency (how "word-like" is it)
    common_bigrams = {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
                      "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"}
    bigrams = [sld[i:i+2].lower() for i in range(len(sld) - 1)]
    common_bigram_ratio = sum(1 for b in bigrams if b in common_bigrams) / max(len(bigrams), 1)

    return {
        "length": length,
        "entropy": round(entropy, 3),
        "consonant_ratio": round(consonant_ratio, 3),
        "digit_ratio": round(digit_ratio, 3),
        "unique_ratio": round(unique_ratio, 3),
        "hyphen_count": hyphen_count,
        "common_bigram_ratio": round(common_bigram_ratio, 3),
    }


def _compute_entropy(values, num_bins):
    """Compute normalized entropy of a list of discrete values."""
    import math
    if not values:
        return 0.0
    freq = defaultdict(int)
    for v in values:
        freq[v] += 1
    total = len(values)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    max_entropy = math.log2(min(len(freq), num_bins)) if len(freq) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0
