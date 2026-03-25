"""Anomaly Detection — Isolation Forest per asset.

Learns "normal" behavior per asset over 7-14 days.
Scores each asset's current behavior as anomaly (0=normal, 1=anomalous).
Retrains nightly. Model persisted to disk.
"""

import os
import json
import pickle
import logging
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from . import db
from .features import extract_asset_features

logger = logging.getLogger("ml.anomaly")

MODEL_DIR = Path(os.environ.get("ML_MODEL_DIR", "/tmp/ml-models"))
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Feature columns used by the model (order matters)
FEATURE_COLS = [
    "alerts_count", "alerts_critical", "alerts_high",
    "unique_source_ips", "unique_rules",
    "logs_count", "auth_failures", "auth_successes",
    "dns_queries", "unique_destinations",
    "hour_entropy", "weekend_ratio", "night_ratio",
]


def train():
    """Train Isolation Forest on historical data (last 14 days).

    Collects features for each asset over each 24h window,
    then trains a global model on all asset-day feature vectors.
    """
    logger.info("Training anomaly detection model...")

    all_vectors = []
    all_labels = []  # (asset_id, day) for debugging

    # Collect features for the last 14 days, day by day
    for days_ago in range(14, 0, -1):
        features = extract_asset_features(hours_back=days_ago * 24)
        for asset_id, feats in features.items():
            vector = [feats.get(col, 0) for col in FEATURE_COLS]
            all_vectors.append(vector)
            all_labels.append((asset_id, days_ago))

    if len(all_vectors) < 5:
        logger.warning("Not enough data to train (need at least 5 feature vectors, got %d)", len(all_vectors))
        return False

    X = np.array(all_vectors, dtype=np.float64)

    # Handle NaN/Inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Train Isolation Forest
    # contamination=0.05 means we expect ~5% of training data to be anomalous
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    # Save model
    model_path = MODEL_DIR / "isolation_forest.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    # Save feature means for baseline comparison
    means = {col: float(X[:, i].mean()) for i, col in enumerate(FEATURE_COLS)}
    stds = {col: float(X[:, i].std()) for i, col in enumerate(FEATURE_COLS)}
    stats_path = MODEL_DIR / "feature_stats.json"
    with open(stats_path, "w") as f:
        json.dump({"means": means, "stds": stds, "samples": len(all_vectors),
                    "trained_at": datetime.utcnow().isoformat()}, f, indent=2)

    logger.info("Model trained on %d samples (%d assets × %d days). Saved to %s",
                len(all_vectors), len(set(l[0] for l in all_labels)),
                len(set(l[1] for l in all_labels)), model_path)
    return True


def score_assets():
    """Score all assets with current behavioral features.

    Returns: { asset_id: { score, reason, features } }
    """
    model_path = MODEL_DIR / "isolation_forest.pkl"
    stats_path = MODEL_DIR / "feature_stats.json"

    if not model_path.exists():
        logger.warning("No trained model found. Run train() first.")
        return {}

    with open(model_path, "rb") as f:
        model = pickle.load(f)

    stats = {}
    if stats_path.exists():
        with open(stats_path) as f:
            stats = json.load(f)

    means = stats.get("means", {})
    stds = stats.get("stds", {})

    # Get current features (last 24h)
    features = extract_asset_features(hours_back=24)

    if not features:
        logger.info("No asset features to score.")
        return {}

    results = {}

    for asset_id, feats in features.items():
        vector = np.array([[feats.get(col, 0) for col in FEATURE_COLS]], dtype=np.float64)
        vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)

        # Isolation Forest: decision_function returns negative for anomalies
        raw_score = model.decision_function(vector)[0]
        # Convert to 0-1 where 1 = most anomalous
        # decision_function: positive = normal, negative = anomaly
        # Typical range: -0.5 (very anomalous) to +0.5 (very normal)
        anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))

        # Build explanation: which features deviate most from baseline
        deviations = []
        for i, col in enumerate(FEATURE_COLS):
            current = feats.get(col, 0)
            mean = means.get(col, 0)
            std = stds.get(col, 1)
            if std > 0 and abs(current - mean) > 2 * std:
                direction = "above" if current > mean else "below"
                sigma = abs(current - mean) / std
                deviations.append({
                    "feature": col,
                    "current": current,
                    "baseline_mean": round(mean, 2),
                    "sigma": round(sigma, 1),
                    "direction": direction,
                })

        # Sort by sigma (most deviant first)
        deviations.sort(key=lambda d: d["sigma"], reverse=True)

        # Build human-readable reason
        if deviations:
            top = deviations[0]
            reason = f"{top['feature']} is {top['sigma']}σ {top['direction']} baseline ({top['current']} vs mean {top['baseline_mean']})"
        else:
            reason = "Within normal baseline"

        results[asset_id] = {
            "score": round(anomaly_score, 3),
            "reason": reason,
            "features": feats,
            "deviations": deviations[:5],  # Top 5
            "baseline_match": anomaly_score < 0.3,
        }

        # Persist score to DB
        db.write_ml_score(asset_id, anomaly_score, reason, feats)

    logger.info("Scored %d assets. Anomalies (>0.7): %d",
                len(results),
                sum(1 for r in results.values() if r["score"] > 0.7))

    return results


def create_findings_for_anomalies(scores, threshold=0.7):
    """Create findings in the DB for anomalous assets."""
    findings_created = 0

    for asset_id, data in scores.items():
        if data["score"] < threshold:
            continue

        severity = "CRITICAL" if data["score"] > 0.9 else "HIGH" if data["score"] > 0.8 else "MEDIUM"

        # Build description from deviations
        desc_parts = [f"Anomaly score: {data['score']:.2f} ({data['reason']})"]
        for d in data.get("deviations", [])[:3]:
            desc_parts.append(f"  - {d['feature']}: {d['current']} ({d['sigma']}σ {d['direction']} baseline)")

        description = "\n".join(desc_parts)

        db.write_finding(
            skill_id="ml-anomaly-detector",
            title=f"Behavioral anomaly detected: {asset_id} (score {data['score']:.2f})",
            description=description,
            severity=severity,
            category="ml-anomaly",
            asset=asset_id,
            source="ML Isolation Forest",
            metadata={
                "ml_score": data["score"],
                "deviations": data.get("deviations", []),
                "features": data["features"],
            },
        )
        findings_created += 1
        logger.warning("ANOMALY: %s — score %.2f — %s", asset_id, data["score"], data["reason"])

    return findings_created
