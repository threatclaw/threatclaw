"""Tests for skill-CHANGEME."""

import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path for imports
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import check


class TestSkill(unittest.TestCase):
    """Test the main check function."""

    @patch("main.urllib.request.urlopen")
    def test_detects_issue(self, mock_urlopen):
        """Should return findings when an issue is detected."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"risk_score": 85}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        findings = check("test-api-key", "suspicious.example.com")

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("suspicious.example.com", findings[0]["asset"])

    @patch("main.urllib.request.urlopen")
    def test_clean_result(self, mock_urlopen):
        """Should return empty list when no issues found."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"risk_score": 10}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        findings = check("test-api-key", "clean.example.com")

        self.assertEqual(len(findings), 0)

    @patch("main.urllib.request.urlopen")
    def test_handles_api_error(self, mock_urlopen):
        """Should handle API errors gracefully without crashing."""
        mock_urlopen.side_effect = Exception("Connection refused")

        findings = check("test-api-key", "unreachable.example.com")

        self.assertEqual(len(findings), 0)  # Graceful failure, no crash


if __name__ == "__main__":
    unittest.main()
