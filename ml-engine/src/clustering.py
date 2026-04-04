"""Behavioral asset clustering. See ADR-003."""

import os
import json
import logging
from pathlib import Path
from collections import defaultdict

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from . import db
from .features import extract_asset_features

logger = logging.getLogger("ml.clustering")

MODEL_DIR = Path(os.environ.get("ML_MODEL_DIR", "/tmp/ml-models"))

FEATURE_COLS = [
    "alerts_count", "alerts_critical", "alerts_high",
    "unique_source_ips", "unique_rules",
    "logs_count", "auth_failures", "auth_successes",
    "dns_queries", "unique_destinations",
    "hour_entropy", "weekend_ratio", "night_ratio",
]


def run_clustering():
    """Run behavioral clustering and detect outliers. See ADR-003.

    Returns: {
        clusters: { cluster_id: [asset_ids] },
        outliers: [{ asset_id, reason, distance }],
        noise: [asset_ids],  # assets that don't fit any cluster
    }
    """
    logger.info("Running behavioral clustering (DBSCAN)...")

    # Get features for last 7 days (more stable than 24h)
    features = extract_asset_features(hours_back=168)

    if len(features) < 5:
        logger.info("Not enough assets for clustering (need >= 5, got %d). Skipping.", len(features))
        return {"clusters": {}, "outliers": [], "noise": []}

    asset_ids = list(features.keys())
    X = np.array([[features[aid].get(col, 0) for col in FEATURE_COLS] for aid in asset_ids], dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Normalize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # See ADR-003
    dbscan = DBSCAN(eps=1.5, min_samples=2, metric="euclidean")
    labels = dbscan.fit_predict(X_scaled)

    # Build clusters
    clusters = defaultdict(list)
    noise_assets = []

    for i, label in enumerate(labels):
        if label == -1:
            noise_assets.append(asset_ids[i])
        else:
            clusters[int(label)].append(asset_ids[i])

    # Compute cluster centroids
    centroids = {}
    for cluster_id, members in clusters.items():
        indices = [asset_ids.index(m) for m in members]
        centroids[cluster_id] = X_scaled[indices].mean(axis=0)

    # Detect outliers within clusters (mouton noir)
    outliers = []
    for cluster_id, members in clusters.items():
        if len(members) < 2:
            continue

        centroid = centroids[cluster_id]
        distances = []

        for member in members:
            idx = asset_ids.index(member)
            dist = np.linalg.norm(X_scaled[idx] - centroid)
            distances.append((member, dist))

        # Mean + 2*std = outlier threshold within the cluster
        dists = [d[1] for d in distances]
        mean_dist = np.mean(dists)
        std_dist = np.std(dists)
        threshold = mean_dist + 2 * std_dist

        for member, dist in distances:
            if dist > threshold and std_dist > 0:
                # Find which features deviate most
                idx = asset_ids.index(member)
                feature_diffs = X_scaled[idx] - centroid
                top_feature_idx = np.argmax(np.abs(feature_diffs))
                top_feature = FEATURE_COLS[top_feature_idx]
                direction = "above" if feature_diffs[top_feature_idx] > 0 else "below"

                outliers.append({
                    "asset_id": member,
                    "cluster_id": cluster_id,
                    "cluster_size": len(members),
                    "distance": round(float(dist), 3),
                    "threshold": round(float(threshold), 3),
                    "sigma": round(float((dist - mean_dist) / std_dist), 1) if std_dist > 0 else 0,
                    "reason": f"{top_feature} is {direction} cluster average (cluster of {len(members)} similar assets)",
                    "top_deviation_feature": top_feature,
                })

    # Save clustering results
    result = {
        "clusters": {str(k): v for k, v in clusters.items()},
        "outliers": outliers,
        "noise": noise_assets,
        "total_assets": len(asset_ids),
        "total_clusters": len(clusters),
        "computed_at": __import__("datetime").datetime.utcnow().isoformat(),
    }

    results_path = MODEL_DIR / "clustering_results.json"
    with open(results_path, "w") as f:
        json.dump(result, f, indent=2)

    logger.info(
        "DBSCAN: %d assets → %d clusters + %d noise. Outliers: %d",
        len(asset_ids), len(clusters), len(noise_assets), len(outliers)
    )

    return result


def create_findings_for_outliers(result):
    """Create findings for assets that deviate from their cluster."""
    findings_created = 0

    for outlier in result.get("outliers", []):
        title = f"Behavioral outlier: {outlier['asset_id']} deviates from {outlier['cluster_size']} similar assets"
        description = (
            f"Asset '{outlier['asset_id']}' is {outlier['sigma']}σ away from its peer group "
            f"(cluster of {outlier['cluster_size']} assets with similar behavior).\n"
            f"Main deviation: {outlier['reason']}\n"
            f"Distance: {outlier['distance']} (threshold: {outlier['threshold']})"
        )

        severity = "HIGH" if outlier["sigma"] > 3 else "MEDIUM"

        db.write_finding(
            skill_id="ml-clustering",
            title=title,
            description=description,
            severity=severity,
            category="ml-clustering",
            asset=outlier["asset_id"],
            source="ML DBSCAN Clustering",
            metadata={
                "cluster_id": outlier["cluster_id"],
                "cluster_size": outlier["cluster_size"],
                "distance": outlier["distance"],
                "sigma": outlier["sigma"],
                "top_deviation": outlier["top_deviation_feature"],
            },
        )
        findings_created += 1
        logger.warning("OUTLIER: %s — %s", outlier["asset_id"], outlier["reason"])

    # Also create findings for noise assets (don't fit any cluster)
    for noise_asset in result.get("noise", []):
        # Try to get hostname for better readability
        asset_info = db.get_asset_info(noise_asset) if hasattr(db, 'get_asset_info') else None
        hostname = asset_info.get("hostname", "") if asset_info else ""
        display_name = f"{hostname} ({noise_asset})" if hostname else noise_asset
        db.write_finding(
            skill_id="ml-clustering",
            title=f"Unclustered asset: {display_name} — unique behavioral pattern",
            description=f"Asset '{display_name}' has a unique behavioral pattern that doesn't match "
                        f"any other asset group. This could indicate a compromised device, "
                        f"a misconfigured service, or a new device not yet profiled. "
                        f"Review this asset in the Assets page.",
            severity="LOW",
            category="ml-clustering",
            asset=noise_asset,
            source="ML DBSCAN Clustering",
            metadata={"noise": True, "hostname": hostname},
        )
        findings_created += 1

    return findings_created
