from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from secscore.core.engine import EngineInput, run_engine
from secscore.core.reporting import render_pr_comment

EXIT = {"PASS": 0, "REVIEW": 1, "FAIL": 2}

def main() -> int:
    parser = argparse.ArgumentParser(prog="secscore", description="SecScore - Security Score that matters.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("pr", help="Run SecScore for Pull Requests (PR mode)")
    pr.add_argument("--findings", required=True, help="Path to findings.json. The parsed results from the scanners")
    pr.add_argument("--policy", required=True, help="Path to policy-pr.yml")
    pr.add_argument("--out", default="pr-comment.md", help="Path to output PR comment markdown")
    pr.add_argument("--json-out", default="secscore-result.json", help="Path to output JSON result")
    args = parser.parse_args()

    if args.cmd == "pr":
        findings = json.loads(Path(args.findings).read_text(encoding="utf-8"))
        policy = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))

        result = run_engine(EngineInput(findings=findings, policy=policy, mode="pull_request"))

        # markdown comment
        md = render_pr_comment(result)
        Path(args.out).write_text(md, encoding="utf-8")

        # machine-readable output (útil pro adapter GitHub/GitLab/Azure)
        out_json = {
            "score": result.score,
            "decision": result.decision,
            "reasons": result.reasons,
            "hard_fails": [hf.__dict__ for hf in result.hard_fails],
            "penalties_total": result.penalties_total,
            "findings_new_count": len(result.findings_new),
            "findings_shown_count": len(result.findings_shown),
        }
        Path(args.json_out).write_text(json.dumps(out_json, indent=2), encoding="utf-8")

        print(md)  # opcional: também imprime no log do job
        return EXIT[result.decision]

    return 3

if __name__ == "__main__":
    raise SystemExit(main())