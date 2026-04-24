from __future__ import annotations

import sys
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from secscore.cli.main import _build_maria_submission_payload, main


ROOT = Path(__file__).resolve().parents[1]
SARIF_REVIEW = ROOT / "tests" / "fixtures" / "review.sarif"
POLICY_PR = ROOT / "policy" / "policy-pr.yml"


class MariaPayloadTests(unittest.TestCase):
    def test_build_payload_includes_reported_score_decision_and_summary_counts(self):
        args = Namespace(
            maria_repository_id="f427f613-de06-43f6-aec0-a8dfe7b227a5",
            maria_submission_key="sub-001",
            maria_commit_sha="abc123",
            maria_branch_name="main",
            maria_pipeline_name="ci",
            maria_pipeline_run_id="run-1",
            maria_pull_request_id="123",
            maria_started_at_utc="2026-04-24T09:00:00Z",
            maria_tool_name="SecScore",
            maria_cli_version="0.4.0",
            branch=None,
        )
        result = SimpleNamespace(
            score=84,
            decision="REVIEW",
            findings_new=[
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "medium"},
                {"severity": "low"},
            ],
        )
        payload = _build_maria_submission_payload(args, result, {"findings": [{"id": "x"}]})

        self.assertEqual(payload["Score"], 84)
        self.assertEqual(payload["Decision"], "REVIEW")
        self.assertEqual(payload["Summary"], {"Critical": 1, "High": 1, "Medium": 2, "Low": 1})
        self.assertEqual(payload["RepositoryId"], "f427f613-de06-43f6-aec0-a8dfe7b227a5")
        self.assertEqual(payload["Findings"], [{"id": "x"}])


class MariaStrictModeTests(unittest.TestCase):
    def _run_main_with_http_error(self, status_code: int) -> int:
        argv = [
            "secscore",
            "pr",
            "--sarif",
            str(SARIF_REVIEW),
            "--policy",
            str(POLICY_PR),
            "--no-diff-aware",
            "--maria-url",
            "http://localhost:5213/api/secscore/submissions",
            "--maria-repository-id",
            "f427f613-de06-43f6-aec0-a8dfe7b227a5",
            "--token",
            "maria_ss_test_test",
            "--maria-strict",
            "--out",
            "tmp-pr.md",
            "--json-out",
            "tmp-result.json",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch("secscore.cli.main.render_terminal", return_value=None),
            patch(
                "secscore.adapters.maria_provider.send_submission",
                side_effect=requests.HTTPError(f"{status_code} Client Error"),
            ),
        ):
            return main()

    def test_maria_strict_returns_fail_on_400(self):
        self.assertEqual(self._run_main_with_http_error(400), 2)

    def test_maria_strict_returns_fail_on_401(self):
        self.assertEqual(self._run_main_with_http_error(401), 2)

    def test_maria_strict_returns_fail_on_403(self):
        self.assertEqual(self._run_main_with_http_error(403), 2)


if __name__ == "__main__":
    unittest.main()

