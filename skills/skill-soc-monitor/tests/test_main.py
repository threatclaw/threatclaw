"""Tests for skill-soc-monitor main module.

Covers data models, time-range parsing, Sigma rule application,
alert correlation, triage heuristics, the full run pipeline with
mocked DB, edge cases, and statistics computation.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.main import (
    Alert,
    AlertSeverity,
    AlertStatus,
    Correlation,
    ScanStats,
    SkillInput,
    SkillOutput,
    TriageResult,
    apply_sigma_rules,
    compute_scan_stats,
    correlate_alerts,
    fetch_logs_from_db,
    parse_time_range,
    run,
    triage_alert,
    KNOWN_SAFE_IPS,
)
from src.sigma_engine import SigmaRule, LogSource, load_rules_from_yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    rule_name: str = "Test Rule",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    source: str = "syslog",
    timestamp: str = "2025-01-15T12:00:00+00:00",
    description: str = "Test alert",
    sigma_rule_id: str = "rule-001",
    hostname: str = "prod-web-01",
    source_ip: str = "10.20.30.40",
    username: str = "jdoe",
    mitre_tags: list[str] | None = None,
    status: AlertStatus = AlertStatus.NEW,
) -> Alert:
    return Alert(
        rule_name=rule_name,
        severity=severity,
        source=source,
        timestamp=timestamp,
        description=description,
        sigma_rule_id=sigma_rule_id,
        hostname=hostname,
        source_ip=source_ip,
        username=username,
        mitre_tags=mitre_tags or [],
        status=status,
    )


_SAMPLE_SIGMA_YAML = """\
title: Suspicious Login
id: test-rule-001
status: experimental
level: high
description: Detects suspicious login events
author: test
logsource:
  category: authentication
  product: linux
detection:
  selection:
    EventType: login_failed
  condition: selection
tags:
  - attack.t1110
"""

_SAMPLE_SIGMA_YAML_MEDIUM = """\
title: Process Creation
id: test-rule-002
status: experimental
level: medium
description: Detects process creation
author: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    EventType: process_start
    ProcessName|contains: cmd
  condition: selection
"""


def _load_test_rule(yaml_text: str = _SAMPLE_SIGMA_YAML) -> SigmaRule:
    return load_rules_from_yaml(yaml_text)


# ===========================================================================
# 1. Alert creation and to_dict
# ===========================================================================

class TestAlertModel:
    def test_alert_creation_defaults(self):
        alert = _make_alert()
        assert alert.rule_name == "Test Rule"
        assert alert.severity == AlertSeverity.MEDIUM
        assert alert.status == AlertStatus.NEW
        assert alert.correlation_id == ""
        assert alert.matched_fields == {}

    def test_alert_to_dict_serialises_enums(self):
        alert = _make_alert(severity=AlertSeverity.CRITICAL, status=AlertStatus.INVESTIGATING)
        d = alert.to_dict()
        assert d["severity"] == "critical"
        assert d["status"] == "investigating"
        assert isinstance(d["mitre_tags"], list)
        assert d["hostname"] == "prod-web-01"

    def test_alert_to_dict_contains_all_fields(self):
        alert = _make_alert(mitre_tags=["attack.t1110"])
        d = alert.to_dict()
        expected_keys = {
            "rule_name", "severity", "source", "timestamp", "description",
            "sigma_rule_id", "matched_fields", "hostname", "source_ip",
            "username", "mitre_tags", "status", "triage_notes", "correlation_id",
        }
        assert expected_keys == set(d.keys())


# ===========================================================================
# 2. Time-range parsing
# ===========================================================================

class TestTimeRangeParsing:
    def test_preset_1h(self):
        assert parse_time_range("1h") == timedelta(hours=1)

    def test_preset_24h(self):
        assert parse_time_range("24h") == timedelta(hours=24)

    def test_preset_7d(self):
        assert parse_time_range("7d") == timedelta(days=7)

    def test_arbitrary_hours(self):
        assert parse_time_range("12h") == timedelta(hours=12)

    def test_arbitrary_days(self):
        assert parse_time_range("30d") == timedelta(days=30)

    def test_minutes(self):
        assert parse_time_range("15m") == timedelta(minutes=15)

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Unrecognised"):
            parse_time_range("abc")

    def test_whitespace_tolerance(self):
        assert parse_time_range("  6h  ") == timedelta(hours=6)


# ===========================================================================
# 3. Sigma rule application on sample logs
# ===========================================================================

class TestSigmaRuleApplication:
    def test_matching_log_produces_alert(self):
        rule = _load_test_rule()
        logs = [{"EventType": "login_failed", "hostname": "srv01", "source_ip": "1.2.3.4"}]
        alerts = apply_sigma_rules(logs, [rule])
        assert len(alerts) == 1
        assert alerts[0].rule_name == "Suspicious Login"
        assert alerts[0].severity == AlertSeverity.HIGH
        assert alerts[0].sigma_rule_id == "test-rule-001"

    def test_non_matching_log_produces_no_alert(self):
        rule = _load_test_rule()
        logs = [{"EventType": "login_success", "hostname": "srv01"}]
        alerts = apply_sigma_rules(logs, [rule])
        assert len(alerts) == 0

    def test_multiple_rules_multiple_logs(self):
        rule1 = _load_test_rule(_SAMPLE_SIGMA_YAML)
        rule2 = _load_test_rule(_SAMPLE_SIGMA_YAML_MEDIUM)
        logs = [
            {"EventType": "login_failed", "hostname": "srv01"},
            {"EventType": "process_start", "ProcessName": "cmd.exe", "hostname": "srv02"},
            {"EventType": "other", "hostname": "srv03"},
        ]
        alerts = apply_sigma_rules(logs, [rule1, rule2])
        assert len(alerts) == 2
        rule_names = {a.rule_name for a in alerts}
        assert "Suspicious Login" in rule_names
        assert "Process Creation" in rule_names

    def test_extracts_hostname_source_ip_username(self):
        rule = _load_test_rule()
        logs = [{
            "EventType": "login_failed",
            "hostname": "web-01",
            "source_ip": "192.168.1.50",
            "username": "admin",
        }]
        alerts = apply_sigma_rules(logs, [rule])
        assert alerts[0].hostname == "web-01"
        assert alerts[0].source_ip == "192.168.1.50"
        assert alerts[0].username == "admin"

    def test_mitre_tags_propagated(self):
        rule = _load_test_rule()
        logs = [{"EventType": "login_failed"}]
        alerts = apply_sigma_rules(logs, [rule])
        assert "attack.t1110" in alerts[0].mitre_tags


# ===========================================================================
# 4. Alert correlation
# ===========================================================================

class TestAlertCorrelation:
    def test_same_source_ip_correlation(self):
        base_ts = "2025-01-15T12:00:00+00:00"
        ts2 = "2025-01-15T12:02:00+00:00"
        alerts = [
            _make_alert(source_ip="10.0.0.5", timestamp=base_ts, rule_name="Rule A"),
            _make_alert(source_ip="10.0.0.5", timestamp=ts2, rule_name="Rule B"),
        ]
        corrs = correlate_alerts(alerts)
        same_ip = [c for c in corrs if c.pattern == "same_source_ip"]
        assert len(same_ip) >= 1
        assert "10.0.0.5" in same_ip[0].description

    def test_same_username_correlation(self):
        base_ts = "2025-01-15T12:00:00+00:00"
        ts2 = "2025-01-15T12:01:00+00:00"
        alerts = [
            _make_alert(username="admin", timestamp=base_ts, source_ip="1.1.1.1"),
            _make_alert(username="admin", timestamp=ts2, source_ip="1.1.1.1"),
        ]
        corrs = correlate_alerts(alerts)
        user_corrs = [c for c in corrs if c.pattern == "same_username"]
        assert len(user_corrs) >= 1
        assert "admin" in user_corrs[0].description

    def test_same_hostname_correlation(self):
        base_ts = "2025-01-15T12:00:00+00:00"
        ts2 = "2025-01-15T12:03:00+00:00"
        alerts = [
            _make_alert(hostname="db-server", timestamp=base_ts, source_ip="1.1.1.1"),
            _make_alert(hostname="db-server", timestamp=ts2, source_ip="1.1.1.2"),
        ]
        corrs = correlate_alerts(alerts)
        host_corrs = [c for c in corrs if c.pattern == "same_hostname"]
        assert len(host_corrs) >= 1
        assert "db-server" in host_corrs[0].description

    def test_brute_force_detection(self):
        base = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alerts = []
        for i in range(6):
            ts = (base + timedelta(minutes=i)).isoformat()
            alerts.append(_make_alert(
                rule_name="Failed Login Attempt",
                description="Brute force failed authentication",
                source_ip="10.99.99.99",
                timestamp=ts,
                username=f"user{i}",
                hostname=f"host{i}",
            ))
        corrs = correlate_alerts(alerts)
        brute = [c for c in corrs if c.pattern == "brute_force"]
        assert len(brute) >= 1
        assert brute[0].confidence >= 0.7

    def test_lateral_movement_detection(self):
        base_ts = "2025-01-15T12:00:00+00:00"
        ts2 = "2025-01-15T12:01:00+00:00"
        alerts = [
            _make_alert(username="attacker", source_ip="10.0.0.1", timestamp=base_ts, hostname="h1"),
            _make_alert(username="attacker", source_ip="10.0.0.2", timestamp=ts2, hostname="h2"),
        ]
        corrs = correlate_alerts(alerts)
        lateral = [c for c in corrs if c.pattern == "lateral_movement"]
        assert len(lateral) >= 1
        assert "2 different IPs" in lateral[0].description

    def test_no_correlation_for_single_alert(self):
        alerts = [_make_alert()]
        corrs = correlate_alerts(alerts)
        # With only 1 alert, no grouping should produce correlations
        # (except patterns that check for single alerts won't trigger either)
        assert all(len(c.alerts) >= 2 for c in corrs)

    def test_empty_alerts_no_correlations(self):
        corrs = correlate_alerts([])
        assert corrs == []


# ===========================================================================
# 5. Triage heuristics
# ===========================================================================

class TestTriageHeuristics:
    def test_known_safe_ip_flagged_as_fp(self):
        alert = _make_alert(source_ip="127.0.0.1")
        result = triage_alert(alert)
        assert result.is_false_positive is True
        assert result.confidence >= 0.9
        assert "known-safe" in result.reasoning.lower()

    def test_dev_hostname_flagged_as_fp(self):
        alert = _make_alert(hostname="dev-app-01", source_ip="8.8.8.8")
        result = triage_alert(alert)
        assert result.is_false_positive is True
        assert result.confidence >= 0.7
        assert "test/dev" in result.reasoning.lower()

    def test_informational_flagged_as_fp(self):
        alert = _make_alert(severity=AlertSeverity.INFORMATIONAL, source_ip="8.8.8.8")
        result = triage_alert(alert)
        assert result.is_false_positive is True
        assert result.confidence >= 0.8

    def test_night_time_auth_not_fp(self):
        alert = _make_alert(
            timestamp="2025-01-15T03:00:00+00:00",
            rule_name="Auth Failure",
            description="Failed login attempt",
            source_ip="8.8.8.8",
            hostname="prod-01",
        )
        result = triage_alert(alert)
        assert result.is_false_positive is False
        assert result.confidence >= 0.8
        assert "night-time" in result.reasoning.lower()

    def test_default_no_heuristic_match(self):
        alert = _make_alert(
            source_ip="8.8.8.8",
            hostname="prod-web-01",
            timestamp="2025-01-15T14:00:00+00:00",
            severity=AlertSeverity.HIGH,
        )
        result = triage_alert(alert)
        assert "default assessment" in result.reasoning.lower()


# ===========================================================================
# 6. Full run with mocked DB
# ===========================================================================

class TestRunPipeline:
    @pytest.mark.asyncio
    async def test_run_with_no_logs(self):
        """When DB returns empty, run should succeed with zero alerts."""
        with patch("src.main.fetch_logs_from_db", new_callable=AsyncMock, return_value=[]):
            with patch("src.main.load_rules_from_directory", return_value=[]):
                output = await run(SkillInput())
        assert output.success is True
        assert output.alerts == []
        assert output.total_logs_analyzed == 0

    @pytest.mark.asyncio
    async def test_run_with_matching_logs(self):
        """Full pipeline with logs that match a Sigma rule."""
        rule = _load_test_rule()
        logs = [
            {"EventType": "login_failed", "hostname": "srv01", "source_ip": "10.0.0.5",
             "username": "admin", "tag": "auth", "timestamp": "2025-01-15T12:00:00+00:00"},
        ]
        with patch("src.main.fetch_logs_from_db", new_callable=AsyncMock, return_value=logs):
            with patch("src.main.load_rules_from_directory", return_value=[rule]):
                output = await run(SkillInput(time_range="1h"))
        assert output.success is True
        assert len(output.alerts) == 1
        assert output.total_logs_analyzed == 1
        assert output.rules_matched == 1

    @pytest.mark.asyncio
    async def test_run_with_auto_triage(self):
        """When auto_triage=True, alerts should have triage_notes populated."""
        rule = _load_test_rule()
        logs = [
            {"EventType": "login_failed", "hostname": "dev-app",
             "source_ip": "127.0.0.1", "tag": "auth",
             "timestamp": "2025-01-15T12:00:00+00:00"},
        ]
        with patch("src.main.fetch_logs_from_db", new_callable=AsyncMock, return_value=logs):
            with patch("src.main.load_rules_from_directory", return_value=[rule]):
                output = await run(SkillInput(auto_triage=True))
        assert output.success is True
        assert len(output.alerts) == 1
        # The alert should be triaged as false positive (safe IP + dev hostname)
        assert output.alerts[0].status == AlertStatus.FALSE_POSITIVE
        assert output.alerts[0].triage_notes != ""
        assert output.false_positive_rate == 1.0

    @pytest.mark.asyncio
    async def test_run_handles_db_error_gracefully(self):
        """When DB fetch fails, run returns success=False with error."""
        with patch("src.main.fetch_logs_from_db", new_callable=AsyncMock,
                    side_effect=RuntimeError("connection refused")):
            output = await run(SkillInput())
        assert output.success is False
        assert "connection refused" in output.error

    @pytest.mark.asyncio
    async def test_run_summary_contains_stats(self):
        rule = _load_test_rule()
        logs = [
            {"EventType": "login_failed", "tag": "auth",
             "timestamp": "2025-01-15T12:00:00+00:00"},
            {"EventType": "other", "tag": "auth",
             "timestamp": "2025-01-15T12:01:00+00:00"},
        ]
        with patch("src.main.fetch_logs_from_db", new_callable=AsyncMock, return_value=logs):
            with patch("src.main.load_rules_from_directory", return_value=[rule]):
                output = await run(SkillInput())
        assert "Scanned 2 logs" in output.summary
        assert "Matched 1 alerts" in output.summary


# ===========================================================================
# 7. Edge cases
# ===========================================================================

class TestEdgeCases:
    def test_apply_sigma_rules_empty_logs(self):
        rule = _load_test_rule()
        alerts = apply_sigma_rules([], [rule])
        assert alerts == []

    def test_apply_sigma_rules_empty_rules(self):
        logs = [{"EventType": "login_failed"}]
        alerts = apply_sigma_rules(logs, [])
        assert alerts == []

    def test_correlate_no_ip_no_user_no_host(self):
        alerts = [
            _make_alert(source_ip="", username="", hostname=""),
            _make_alert(source_ip="", username="", hostname=""),
        ]
        corrs = correlate_alerts(alerts)
        # No grouping dimension available
        assert corrs == []

    @pytest.mark.asyncio
    async def test_run_with_empty_input(self):
        with patch("src.main.fetch_logs_from_db", new_callable=AsyncMock, return_value=[]):
            with patch("src.main.load_rules_from_directory", return_value=[]):
                output = await run(SkillInput(sources=[], sigma_rulesets=[]))
        assert output.success is True
        assert output.alerts == []
        assert output.correlations == []

    def test_alert_status_enum_values(self):
        assert AlertStatus.NEW.value == "new"
        assert AlertStatus.INVESTIGATING.value == "investigating"
        assert AlertStatus.RESOLVED.value == "resolved"
        assert AlertStatus.FALSE_POSITIVE.value == "false_positive"

    def test_alert_severity_enum_values(self):
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.INFORMATIONAL.value == "informational"


# ===========================================================================
# 8. Correlation confidence scoring
# ===========================================================================

class TestCorrelationConfidence:
    def test_confidence_increases_with_cluster_size(self):
        base = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        small_cluster = [
            _make_alert(source_ip="10.0.0.5", timestamp=(base + timedelta(seconds=i * 30)).isoformat(),
                        rule_name=f"Rule {i}", hostname=f"h{i}", username=f"u{i}")
            for i in range(2)
        ]
        large_cluster = [
            _make_alert(source_ip="10.0.0.5", timestamp=(base + timedelta(seconds=i * 30)).isoformat(),
                        rule_name=f"Rule {i}", hostname=f"h{i}", username=f"u{i}")
            for i in range(5)
        ]
        small_corrs = correlate_alerts(small_cluster)
        large_corrs = correlate_alerts(large_cluster)

        small_ip = [c for c in small_corrs if c.pattern == "same_source_ip"]
        large_ip = [c for c in large_corrs if c.pattern == "same_source_ip"]

        assert len(small_ip) >= 1
        assert len(large_ip) >= 1
        # Larger cluster -> higher confidence
        assert large_ip[0].confidence >= small_ip[0].confidence

    def test_brute_force_confidence_capped_at_1(self):
        base = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert(
                source_ip="10.0.0.99",
                timestamp=(base + timedelta(seconds=i * 10)).isoformat(),
                rule_name="Failed Login",
                description="Brute force attempt",
                hostname=f"h{i}",
                username=f"u{i}",
            )
            for i in range(20)
        ]
        corrs = correlate_alerts(alerts)
        for c in corrs:
            assert c.confidence <= 1.0


# ===========================================================================
# 9. Statistics calculation
# ===========================================================================

class TestScanStats:
    def test_compute_scan_stats_basic(self):
        alerts = [
            _make_alert(sigma_rule_id="r1"),
            _make_alert(sigma_rule_id="r2"),
            _make_alert(sigma_rule_id="r1"),  # duplicate rule
        ]
        stats = compute_scan_stats(
            total_logs=100,
            alerts=alerts,
            rules_loaded=10,
            duration=1.5,
        )
        assert stats.total_logs == 100
        assert stats.matched_logs == 3
        assert stats.rules_loaded == 10
        assert stats.rules_matched == 2  # r1 and r2
        assert stats.scan_duration == 1.5

    def test_compute_scan_stats_empty(self):
        stats = compute_scan_stats(total_logs=0, alerts=[], rules_loaded=0, duration=0.01)
        assert stats.total_logs == 0
        assert stats.matched_logs == 0
        assert stats.rules_matched == 0

    def test_compute_scan_stats_no_rule_ids(self):
        alerts = [_make_alert(sigma_rule_id="")]
        stats = compute_scan_stats(total_logs=5, alerts=alerts, rules_loaded=3, duration=0.5)
        assert stats.matched_logs == 1
        assert stats.rules_matched == 0  # empty string excluded
