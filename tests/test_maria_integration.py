from __future__ import annotations

import sys
import unittest
import json
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from secscore.cli.main import _build_maria_submission_payload, _resolve_cli_path, main
from secscore.adapters.maria_provider import build_secscore_policy_from_maria
from secscore.adapters.maria_provider import _validate_maria_url
from secscore.core.engine import EngineInput, run_engine


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


class SecurityHardeningTests(unittest.TestCase):
    def test_cli_paths_must_stay_inside_workspace(self):
        outside = ROOT.parent / "outside.json"

        with self.assertRaises(ValueError):
            _resolve_cli_path(str(outside), "Test path")

    def test_maria_url_blocks_localhost_by_default(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                _validate_maria_url("http://localhost:5213/api/secscore/submissions")

    def test_maria_url_allows_localhost_with_explicit_opt_in(self):
        with patch.dict("os.environ", {"SECSCORE_ALLOW_PRIVATE_MARIA_URLS": "true"}):
            self.assertEqual(
                _validate_maria_url("http://localhost:5213/api/secscore/submissions"),
                "http://localhost:5213/api/secscore/submissions",
            )


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
            "--maria-import-policy",
            "false",
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


class HtmlOutputTests(unittest.TestCase):
    def test_html_output_generates_report_from_standard_json(self):
        json_out = Path("tmp-html-result.json")
        html_out = Path("tmp-secscore-report.html")
        for path in [json_out, html_out]:
            if path.exists():
                path.unlink()

        argv = [
            "secscore",
            "pr",
            "--sarif",
            str(SARIF_REVIEW),
            "--policy",
            str(POLICY_PR),
            "--no-diff-aware",
            "--out",
            "tmp-html-pr.md",
            "--json-out",
            str(json_out),
            "--html-output",
            "true",
            "--html-out",
            str(html_out),
        ]
        with (
            patch.object(sys, "argv", argv),
            patch("secscore.cli.main.render_terminal", return_value=None),
        ):
            main()

        self.assertTrue(json_out.exists())
        self.assertTrue(html_out.exists())

        data = json.loads(json_out.read_text(encoding="utf-8"))
        html = html_out.read_text(encoding="utf-8")
        self.assertEqual(data["decision"], "REVIEW")
        self.assertIn("SecScore Report", html)
        self.assertIn(str(json_out), html)
        self.assertIn('"decision": "REVIEW"', html)
        self.assertIn("Execution Parameters", html)
        self.assertIn("secscore pr", html)
        self.assertIn("SecScore version", html)
        self.assertIn(str(POLICY_PR), html)
        self.assertIn("Diff-aware", html)
        self.assertIn("Copy JSON path", html)
        self.assertIn("riskSummary", html)
        self.assertIn("#L", html)


class MariaPolicyImportTests(unittest.TestCase):
    def test_build_secscore_policy_from_maria_overrides_risk_scoring_thresholds(self):
        base_policy = {
            "policy_version": "1.1",
            "mode": "pull_request",
            "decision": {"pass_min_score": 80, "review_min_score": 51, "fail_below_score": 50},
            "scoring": {
                "base_score": 100,
                "penalties": {"critical": 40, "high": 20, "medium": 7, "low": 2, "info": 0},
                "multipliers": {"confidence": {"high": 1.0}},
            },
            "hard_fails": [],
        }
        maria_policy = {
            "thresholds": {
                "pass_min": 90,
                "review_min": 70,
                "fail_min": 0,
                "hard_fail_on_critical": True,
            },
            "scoring": {
                "base_score": 120,
                "penalties": {"critical": 50, "high": 25, "medium": 9, "low": 3},
            },
        }

        merged = build_secscore_policy_from_maria(maria_policy, base_policy)

        self.assertEqual(merged["decision"]["pass_min_score"], 90)
        self.assertEqual(merged["decision"]["review_min_score"], 70)
        self.assertEqual(merged["scoring"]["base_score"], 120)
        self.assertEqual(merged["scoring"]["penalties"]["critical"], 50)
        self.assertEqual(merged["scoring"]["penalties"]["high"], 25)
        self.assertEqual(merged["scoring"]["penalties"]["medium"], 9)
        self.assertEqual(merged["scoring"]["penalties"]["low"], 3)
        self.assertEqual(merged["scoring"]["penalties"]["info"], 0)
        self.assertTrue(any(hf.get("id") == "MARIA_CRITICAL_NEW" for hf in merged["hard_fails"]))

    def test_build_secscore_policy_from_maria_enables_risk_score_model(self):
        base_policy = {
            "decision": {"pass_min_score": 85, "review_min_score": 51},
            "scoring": {"base_score": 100, "penalties": {"critical": 40, "high": 20, "medium": 7, "low": 2, "info": 0}},
            "hard_fails": [],
        }
        maria_policy = {
            "thresholds": {
                "pass_min": 85,
                "review_min": 51,
                "fail_min": 0,
                "pass_max_risk_score": 49,
                "review_max_risk_score": 79,
                "fail_min_risk_score": 80,
            },
            "scoring": {
                "model": "maria_riskscore_v1",
                "risk_weights": {
                    "critical": 10,
                    "high": 5,
                    "medium": 2,
                    "low": 1,
                    "internet_exposure": 12,
                    "third_party_interaction": 8,
                    "api_exposure": 6,
                    "pii_data": 10,
                    "no_encryption": 8,
                    "encryption_bonus": -4,
                    "no_authentication": 8,
                    "authentication_bonus": -3,
                },
                "application_context": {
                    "is_internet_exposed": True,
                    "has_third_party_interaction": True,
                    "has_apis": True,
                    "handles_pii": True,
                    "has_encrypted_data": True,
                    "requires_authentication": True,
                },
                "risk_profile": {
                    "enabled": True,
                    "business_multiplier": 1.25,
                    "data_multiplier": 1.15,
                    "combined_multiplier": 1.4375,
                },
                "base_score": 100,
                "penalties": {"critical": 40, "high": 20, "medium": 7, "low": 2},
            },
        }

        merged = build_secscore_policy_from_maria(maria_policy, base_policy)

        self.assertEqual(merged["decision"]["model"], "risk_score")
        self.assertEqual(merged["decision"]["pass_max_score"], 49)
        self.assertEqual(merged["decision"]["review_max_score"], 79)
        self.assertEqual(merged["scoring"]["model"], "maria_riskscore_v1")
        self.assertTrue(merged["scoring"]["risk_profile"]["enabled"])


class MariaRiskScoreEngineTests(unittest.TestCase):
    def test_engine_matches_maria_risk_formula_and_decision(self):
        policy = {
            "decision": {
                "model": "risk_score",
                "pass_min_score": 85,
                "review_min_score": 51,
                "pass_max_score": 49,
                "review_max_score": 79,
            },
            "scoring": {
                "model": "maria_riskscore_v1",
                "base_score": 100,
                "penalties": {"critical": 40, "high": 20, "medium": 7, "low": 2, "info": 0},
                "risk_weights": {
                    "critical": 10,
                    "high": 5,
                    "medium": 2,
                    "low": 1,
                    "internet_exposure": 12,
                    "third_party_interaction": 8,
                    "api_exposure": 6,
                    "pii_data": 10,
                    "no_encryption": 8,
                    "encryption_bonus": -4,
                    "no_authentication": 8,
                    "authentication_bonus": -3,
                },
                "application_context": {
                    "is_internet_exposed": True,
                    "has_third_party_interaction": True,
                    "has_apis": True,
                    "handles_pii": True,
                    "has_encrypted_data": True,
                    "requires_authentication": True,
                },
                "risk_profile": {
                    "enabled": True,
                    "combined_multiplier": 1.4375,
                },
            },
            "hard_fails": [],
            "ignore_paths": [],
            "suppressions": {},
            "reporting": {},
        }
        findings = {
            "findings": [
                {"severity": "critical", "is_new": True, "asset": {"path": "src/a.py"}},
                {"severity": "high", "is_new": True, "asset": {"path": "src/b.py"}},
                {"severity": "high", "is_new": True, "asset": {"path": "src/c.py"}},
                {"severity": "medium", "is_new": True, "asset": {"path": "src/d.py"}},
            ]
        }

        result = run_engine(EngineInput(findings=findings, policy=policy))

        # raw = (1*10)+(2*5)+(1*2)=22
        # context = 12+8+6+10-4-3 = 29
        # base = clamp(22+29)=51
        # final = round_away(51*1.4375)=73
        self.assertEqual(result.score, 73)
        self.assertEqual(result.decision, "REVIEW")


if __name__ == "__main__":
    unittest.main()
