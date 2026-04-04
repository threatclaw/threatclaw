"""ThreatClaw ML Engine — main entry point.

Modes:
  1. Train: Retrain all models (run nightly via cron or on-demand)
  2. Score: Score all assets + DNS domains, create findings for anomalies
  3. Daemon: Run scoring every 5 minutes, retrain nightly

The ML Engine is a standalone process that:
- Reads from PostgreSQL (same DB as the Rust backend)
- Writes findings and ML scores back to PostgreSQL
- The Intelligence Engine reads ML scores to adjust alert severity
"""

import os
import sys
import time
import logging
import schedule
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ml.main")


def run_train():
    """Train all ML models + nightly DB maintenance."""
    from .anomaly_detector import train as train_anomaly
    from .dga_detector import train as train_dga
    from . import db as _db

    logger.info("═══ ML TRAINING + MAINTENANCE START ═══")

    # DB maintenance first (cleanup old data, vacuum)
    try:
        _db.run_maintenance(retention_days=90)
    except Exception as e:
        logger.warning("DB maintenance failed: %s", e)

    ok_anomaly = train_anomaly()
    ok_dga = train_dga()

    logger.info("═══ ML TRAINING COMPLETE ═══ anomaly=%s dga=%s", ok_anomaly, ok_dga)
    return ok_anomaly or ok_dga


def run_clustering():
    """Run behavioral clustering and detect outliers. See ADR-003."""
    from .clustering import run_clustering as cluster, create_findings_for_outliers

    logger.info("── ML CLUSTERING START ──")

    result = cluster()
    findings = create_findings_for_outliers(result)

    logger.info(
        "── ML CLUSTERING COMPLETE ── clusters=%d outliers=%d noise=%d findings=%d",
        result.get("total_clusters", 0),
        len(result.get("outliers", [])),
        len(result.get("noise", [])),
        findings,
    )

    return result


def run_score():
    """Score all assets and DNS domains, create findings."""
    from .anomaly_detector import score_assets, create_findings_for_anomalies
    from .dga_detector import score_domains, create_findings_for_dga
    from .context import get_context_multipliers, adjust_score

    logger.info("── ML SCORING START ──")

    # Score assets
    raw_scores = score_assets()
    context = get_context_multipliers()

    # Adjust scores with company context
    adjusted_scores = {}
    for asset_id, data in raw_scores.items():
        adj_score, adj_reason = adjust_score(data["score"], data["features"], context)
        adjusted_scores[asset_id] = {
            **data,
            "score": adj_score,
            "raw_score": data["score"],
            "context_reason": adj_reason,
            "baseline_match": adj_score < 0.3,
        }

    # Create findings for anomalies
    anomaly_findings = create_findings_for_anomalies(adjusted_scores, threshold=0.7)

    # Score DNS domains for DGA
    dga_scores = score_domains()
    dga_findings = create_findings_for_dga(dga_scores)

    # Run clustering (every scoring cycle)
    from .clustering import run_clustering as cluster_fn, create_findings_for_outliers
    cluster_result = cluster_fn()
    cluster_findings = create_findings_for_outliers(cluster_result)

    total_assets = len(adjusted_scores)
    anomalies = sum(1 for s in adjusted_scores.values() if s["score"] > 0.7)
    dga_count = sum(1 for s in dga_scores if s["is_dga"])
    outliers = len(cluster_result.get("outliers", []))
    total_findings = anomaly_findings + dga_findings + cluster_findings

    logger.info("── ML SCORING COMPLETE ── assets=%d anomalies=%d dga=%d outliers=%d findings=%d",
                total_assets, anomalies, dga_count, outliers, total_findings)

    return {
        "assets_scored": total_assets,
        "anomalies_detected": anomalies,
        "dga_suspicious": dga_count,
        "cluster_outliers": outliers,
        "clusters": cluster_result.get("total_clusters", 0),
        "findings_created": total_findings,
    }


def run_daemon():
    """Run as a daemon: score every 5 minutes, retrain at 3am."""
    logger.info("ThreatClaw ML Engine starting in daemon mode")

    # Initial train — retry up to 5 times if DB not ready yet
    for attempt in range(5):
        try:
            run_train()
            break
        except Exception as e:
            wait = 10 * (2 ** attempt)
            logger.warning("Initial training failed (attempt %d/5), retrying in %ds: %s", attempt + 1, wait, e)
            time.sleep(wait)

    # Initial score
    try:
        run_score()
    except Exception as e:
        logger.warning("Initial scoring failed, will retry on next cycle: %s", e)

    # Schedule
    schedule.every(5).minutes.do(run_score)
    schedule.every().day.at("03:00").do(run_train)

    logger.info("ML Engine running. Scoring every 5 min, retraining daily at 03:00.")

    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            logger.error("Scheduled task failed (will retry next cycle): %s", e)
        # Write heartbeat every loop (every 30s)
        try:
            from . import db as _db
            _db.write_heartbeat()
        except Exception as e:
            logger.warning("Heartbeat write failed: %s", e)
        time.sleep(30)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "daemon"

    if mode == "train":
        run_train()
    elif mode == "score":
        result = run_score()
        print(f"Results: {result}")
    elif mode == "cluster":
        result = run_clustering()
        print(f"Clusters: {result.get('total_clusters', 0)}, Outliers: {len(result.get('outliers', []))}, Noise: {len(result.get('noise', []))}")
    elif mode == "daemon":
        run_daemon()
    else:
        print(f"Usage: python -m src.main [train|score|cluster|daemon]")
        sys.exit(1)


if __name__ == "__main__":
    main()
