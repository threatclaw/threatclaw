"""Feature extraction from PostgreSQL data for ML models."""

import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta
from . import db


def _is_private_ipv4(s):
    """True for RFC1918 / loopback / link-local IPv4. Mirrors the Rust
    classifier in src/agent/intelligence_engine.rs. Used as a fallback when
    the customer hasn't declared their own internal_networks yet.
    """
    try:
        ip = ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return False
    return isinstance(ip, ipaddress.IPv4Address) and ip.is_private


def _build_monitored_predicate(assets, internal_networks):
    """Return a predicate ``is_monitored(asset_id) -> bool`` that mirrors the
    Rust ``classify_asset`` doctrine. The pool of features fed into DBSCAN
    must contain only assets the customer asked us to monitor — otherwise
    the cluster baseline gets polluted by Internet scanners and every
    legitimate internal host becomes an outlier.
    """
    declared_ids = set()
    for a in assets:
        if a.get("id"):
            declared_ids.add(a["id"])
        if a.get("hostname"):
            declared_ids.add(a["hostname"])
        for ip in (a.get("ip_addresses") or []):
            declared_ids.add(ip)

    declared_networks = []
    for net in internal_networks or []:
        cidr = net.get("cidr") if isinstance(net, dict) else net
        if not cidr:
            continue
        try:
            declared_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue

    def is_monitored(asset_id):
        if not asset_id:
            return False
        if asset_id in declared_ids:
            return True
        # Try to parse as IPv4 for the network checks.
        try:
            ip = ipaddress.ip_address(asset_id)
        except ValueError:
            return False
        # Customer-declared networks take precedence.
        for net in declared_networks:
            if ip in net:
                return True
        # RFC1918 fallback — keeps fresh installs working without the
        # operator having to fill internal_networks immediately.
        return _is_private_ipv4(asset_id)

    return is_monitored


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
    try:
        internal_networks = db.get_internal_networks()
    except Exception:
        internal_networks = []

    # Inventory predicate — drops external IPs from the pool so the cluster
    # baseline is built from monitored assets only.
    is_monitored = _build_monitored_predicate(assets, internal_networks)

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
        if not asset_id or not is_monitored(asset_id):
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
        if not asset_id or not is_monitored(asset_id):
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
    """Compute features for DGA detection on a domain name.

    Analyzes the second-level domain (SLD). For domains with long subdomains
    (potential DNS tunnel/DGA in subdomain), also analyzes the full subdomain.
    Uses 12 features (v2) via the DGA detector module.
    """
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    sld = parts[-2]

    if len(sld) < 3:
        return None

    # Use the v2 feature extractor from dga_detector
    from .dga_detector import compute_features_v2
    return compute_features_v2(sld)


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
