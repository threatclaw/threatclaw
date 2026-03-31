"""ThreatClaw API client for Python skills.

Usage:
    from threatclaw_sdk import ThreatClawClient, Finding, Severity

    client = ThreatClawClient()  # reads TC_API_URL and TC_API_TOKEN from env

    # Report a finding
    client.report_finding(Finding(
        skill_id="skill-vuln-scan",
        title="CVE-2024-1234 detected on nginx",
        severity=Severity.HIGH,
        asset="192.168.1.10",
        source="nuclei",
    ))

    # Read skill config
    config = client.get_config("skill-vuln-scan")
    targets = config.get("targets", "192.168.1.0/24")

    # Record a metric
    client.record_metric("security_score", 72.0)
"""

import json
import os
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Alert, Finding, SkillConfig


class ThreatClawClient:
    """Client for the ThreatClaw Core API."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout: int = 30,
    ):
        self.api_url = (api_url or os.environ.get("TC_API_URL", "http://127.0.0.1:3000")).rstrip("/")
        self.api_token = api_token or os.environ.get("TC_API_TOKEN", "")
        self.timeout = timeout

    def _request(self, method: str, path: str, data: Optional[dict] = None) -> dict:
        url = f"{self.api_url}{path}"
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        body = json.dumps(data).encode() if data else None
        req = Request(url, data=body, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            error_body = e.read().decode() if e.fp else str(e)
            raise RuntimeError(f"API error {e.code}: {error_body}") from e
        except URLError as e:
            raise ConnectionError(f"Cannot reach ThreatClaw API at {self.api_url}: {e}") from e

    # ── Health ──

    def health(self) -> dict:
        """Check API health."""
        return self._request("GET", "/api/tc/health")

    # ── Findings ──

    def report_finding(self, finding: Finding) -> int:
        """Report a security finding. Returns the finding ID."""
        result = self._request("POST", "/api/tc/findings", finding.to_dict())
        return result.get("id", 0)

    def list_findings(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        skill_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """List findings with optional filters."""
        params = []
        if severity:
            params.append(f"severity={severity}")
        if status:
            params.append(f"status={status}")
        if skill_id:
            params.append(f"skill_id={skill_id}")
        params.append(f"limit={limit}")
        qs = "&".join(params)
        result = self._request("GET", f"/api/tc/findings?{qs}")
        return result.get("findings", [])

    def update_finding_status(self, finding_id: int, status: str, resolved_by: Optional[str] = None) -> None:
        """Update the status of a finding."""
        data: dict[str, Any] = {"status": status}
        if resolved_by:
            data["resolved_by"] = resolved_by
        self._request("PUT", f"/api/tc/findings/{finding_id}/status", data)

    # ── Alerts ──

    def list_alerts(self, level: Optional[str] = None, status: Optional[str] = None, limit: int = 100) -> list[dict]:
        """List SOC alerts."""
        params = []
        if level:
            params.append(f"level={level}")
        if status:
            params.append(f"status={status}")
        params.append(f"limit={limit}")
        qs = "&".join(params)
        result = self._request("GET", f"/api/tc/alerts?{qs}")
        return result.get("alerts", [])

    # ── Config ──

    def get_config(self, skill_id: str) -> dict[str, str]:
        """Get configuration for a skill. Returns a dict of key-value pairs."""
        result = self._request("GET", f"/api/tc/config/{skill_id}")
        configs = result.get("config", [])
        return {c["key"]: c["value"] for c in configs}

    def set_config(self, skill_id: str, key: str, value: str) -> None:
        """Set a configuration value for a skill."""
        self._request("POST", f"/api/tc/config/{skill_id}", {"key": key, "value": value})

    # ── Metrics ──

    def record_metric(self, name: str, value: float, labels: Optional[dict] = None) -> None:
        """Record a metric value (e.g., security_score, cloud_score)."""
        self._request("POST", f"/api/tc/findings", {
            "skill_id": "_metrics",
            "title": name,
            "severity": "info",
            "metadata": {"metric_name": name, "metric_value": value, **(labels or {})},
        })

    def get_dashboard_metrics(self) -> dict:
        """Get aggregated dashboard metrics."""
        result = self._request("GET", "/api/tc/metrics")
        return result.get("metrics", {})
