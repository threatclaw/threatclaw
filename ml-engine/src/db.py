"""Database connection and queries for ML Engine."""

import os
import json
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw")


def get_conn():
    return psycopg2.connect(DATABASE_URL)


def get_alerts(hours_back=24, limit=5000):
    """Get recent sigma alerts for feature extraction."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, rule_id, level, title, hostname,
                       source_ip::text as source_ip, username,
                       matched_at, status
                FROM sigma_alerts
                WHERE matched_at > NOW() - INTERVAL '%s hours'
                ORDER BY matched_at DESC
                LIMIT %s
            """, (hours_back, limit))
            return cur.fetchall()
    finally:
        conn.close()


def get_logs(hours_back=24, limit=10000):
    """Get recent logs for feature extraction."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, tag, hostname, data, time
                FROM logs
                WHERE time > NOW() - INTERVAL '%s hours'
                ORDER BY time DESC
                LIMIT %s
            """, (hours_back, limit))
            return cur.fetchall()
    finally:
        conn.close()


def get_assets():
    """Get all active assets."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, name, category, subcategory, role, criticality,
                       ip_addresses, hostname, os, mac_vendor, services
                FROM assets
                WHERE status = 'active'
            """)
            return cur.fetchall()
    finally:
        conn.close()


def get_company_profile():
    """Get company profile for context."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM company_profile WHERE id = 1")
            row = cur.fetchone()
            return row if row else {}
    finally:
        conn.close()


def get_dns_queries(hours_back=24, limit=5000):
    """Get DNS queries from logs (Pi-hole, syslog DNS)."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, hostname, data, time
                FROM logs
                WHERE (tag LIKE '%%dns%%' OR data::text LIKE '%%query:%%' OR data::text LIKE '%%dns_query%%')
                  AND time > NOW() - INTERVAL '%s hours'
                ORDER BY time DESC
                LIMIT %s
            """, (hours_back, limit))
            return cur.fetchall()
    finally:
        conn.close()


def write_finding(skill_id, title, description, severity, category, asset, source, metadata):
    """Write a ML finding to the findings table."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO findings (skill_id, title, description, severity, category, asset, source, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                RETURNING id
            """, (skill_id, title, description, severity, category, asset, source,
                  psycopg2.extras.Json(metadata) if metadata else '{}'))
            conn.commit()
            return cur.fetchone()[0]
    finally:
        conn.close()


def write_ml_score(asset_id, score, reason, features):
    """Write ML anomaly score to dedicated ml_scores table."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            features_json = json.dumps(features) if isinstance(features, dict) else "{}"
            cur.execute("""
                INSERT INTO ml_scores (asset_id, score, reason, features, computed_at)
                VALUES (%s, %s, %s, %s::jsonb, NOW())
                ON CONFLICT (asset_id) DO UPDATE SET
                    score = EXCLUDED.score, reason = EXCLUDED.reason,
                    features = EXCLUDED.features, computed_at = NOW()
            """, (str(asset_id), float(score), str(reason), features_json))
            conn.commit()
    except Exception as e:
        conn.rollback()
        logging.getLogger("ml.db").warning("write_ml_score failed: %s", e)
    finally:
        conn.close()


def run_maintenance(retention_days=90):
    """Run nightly DB maintenance: cleanup + vacuum + analyze."""
    conn = get_conn()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            # Cleanup old data
            cur.execute("SELECT cleanup_old_data(%s)", (retention_days,))
            result = cur.fetchone()
            logging.getLogger("ml.db").info("DB maintenance: %s", result[0] if result else "done")

            # VACUUM ANALYZE critical tables
            for table in ["sigma_alerts", "findings", "logs", "assets", "ml_scores"]:
                try:
                    cur.execute(f"VACUUM ANALYZE {table}")
                except Exception as e:
                    logging.getLogger("ml.db").warning("VACUUM %s failed: %s", table, e)
    except Exception as e:
        logging.getLogger("ml.db").warning("DB maintenance failed: %s", e)
    finally:
        conn.close()


def write_heartbeat():
    """Write ML engine heartbeat to settings."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO settings (user_id, key, value)
                VALUES ('_system', 'ml_heartbeat', %s::jsonb)
                ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """, (json.dumps({"alive": True, "timestamp": datetime.utcnow().isoformat()}),))
            conn.commit()
    except:
        pass
    finally:
        conn.close()


def get_ml_score(asset_id):
    """Read ML anomaly score for an asset."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT score, reason, features FROM ml_scores WHERE asset_id = %s", (asset_id,))
            row = cur.fetchone()
            return row if row else None
    except:
        # Fallback to settings
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT value FROM settings WHERE user_id = 'ml_scores' AND key = %s", (f"score_{asset_id}",))
                row = cur.fetchone()
                return row["value"] if row else None
        except:
            return None
    finally:
        conn.close()
