"""Database connection and queries for ML Engine."""

import os
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
    """Write ML anomaly score to settings table (user_id=ml_scores)."""
    import json
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO settings (user_id, key, value)
                VALUES ('ml_scores', %s, %s::jsonb)
                ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """, (f"score_{asset_id}", json.dumps({
                "asset_id": asset_id,
                "score": score,
                "reason": reason,
                "features": features,
                "computed_at": datetime.utcnow().isoformat(),
            })))
            conn.commit()
    finally:
        conn.close()


def get_ml_score(asset_id):
    """Read ML anomaly score for an asset."""
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT value FROM settings
                WHERE user_id = 'ml_scores' AND key = %s
            """, (f"score_{asset_id}",))
            row = cur.fetchone()
            return row["value"] if row else None
    finally:
        conn.close()
