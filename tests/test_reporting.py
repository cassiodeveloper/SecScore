from __future__ import annotations

import unittest
from types import SimpleNamespace

from secscore.core.reporting import render_pr_comment


def _result(findings_shown, reasons=None, decision="REVIEW", score=70):
    return SimpleNamespace(
        decision=decision,
        score=score,
        findings_shown=list(findings_shown),
        reasons=list(reasons or []),
    )


def _finding(title="Issue", severity="high", path=None, line=None, **metadata):
    f = {"title": title, "severity": severity}
    if path is not None:
        f["asset"] = {"path": path, "line": line}
    if metadata:
        f["metadata"] = metadata
    return f


class ReportingConfigTests(unittest.TestCase):
    def test_policy_max_findings_in_comment_is_honored(self):
        findings = [_finding(title=f"F{i}", severity="high") for i in range(4)]
        result = _result(findings)
        policy_config = {"reporting": {"max_findings_in_comment": 2}}

        md = render_pr_comment(result, policy="p.yml", policy_config=policy_config)

        self.assertIn("F0", md)
        self.assertIn("F1", md)
        self.assertNotIn("F3", md)
        self.assertIn("_+2 additional findings not shown._", md)

    def test_policy_max_reasons_is_honored(self):
        result = _result([_finding()], reasons=["r1", "r2", "r3"])
        policy_config = {"reporting": {"max_reasons": 1}}

        md = render_pr_comment(result, policy="p.yml", policy_config=policy_config)

        self.assertIn("- r1", md)
        self.assertNotIn("- r2", md)
        self.assertIn("_+2 more reasons not shown._", md)

    def test_defaults_apply_without_policy_config(self):
        findings = [_finding(title=f"F{i}") for i in range(7)]
        result = _result(findings)

        md = render_pr_comment(result, policy="p.yml")

        # DEFAULT_MAX_FINDINGS == 5 -> 2 remaining not shown.
        self.assertIn("_+2 additional findings not shown._", md)

    def test_include_fields_excludes_metadata_and_location(self):
        result = _result(
            [_finding(path="src/a.py", line=10, cve="CVE-2026-0001", package="left-pad")]
        )
        policy_config = {"reporting": {"include_fields": ["title", "severity"]}}

        md = render_pr_comment(result, policy="p.yml", policy_config=policy_config)

        self.assertNotIn("CVE-2026-0001", md)
        self.assertNotIn("src/a.py", md)


class ReportingMarkdownHardeningTests(unittest.TestCase):
    def test_title_markdown_link_injection_is_neutralized(self):
        malicious = "Click [here](http://evil.example) and `code`"
        result = _result([_finding(title=malicious)])

        md = render_pr_comment(result, policy="p.yml")

        # The raw link/code syntax must not survive unescaped.
        self.assertNotIn("[here](http://evil.example)", md)
        self.assertIn(r"\[here\]", md)
        self.assertNotIn("and `code`", md)

    def test_location_path_is_percent_encoded_in_link(self):
        result = _result([_finding(path="src/weird (v2).py", line=5)])

        md = render_pr_comment(result, policy="p.yml")

        # Parentheses in the href would otherwise break the Markdown link.
        self.assertIn("./src/weird%20%28v2%29.py#L5", md)


if __name__ == "__main__":
    unittest.main()
