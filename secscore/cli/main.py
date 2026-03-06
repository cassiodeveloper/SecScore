from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from secscore.core.engine import EngineInput, run_engine
from secscore.core.reporting import render_pr_comment

EXIT = {"PASS": 0, "REVIEW": 1, "FAIL": 2}

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secscore",
        description="SecScore - Security Score that matters."
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("pr", help="Run SecScore for Pull Requests (PR mode)")

    pr.add_argument("--findings", help="Path to findings.json")
    pr.add_argument("--sarif", help="Path to SARIF results file")
    pr.add_argument("--policy", required=True, help="Path to policy-pr.yml")

    pr.add_argument("--out", default="pr-comment.md", help="Output PR comment markdown")
    pr.add_argument("--json-out", default="secscore-result.json", help="Output JSON result")

    # provider parameters
    pr.add_argument("--provider")
    pr.add_argument("--checkmarx-project")
    pr.add_argument("--checkmarx-base-url")
    pr.add_argument("--checkmarx-token")
    pr.add_argument("--branch")
    pr.add_argument("--checkmarx-tenant")

    args = parser.parse_args()

    if args.cmd == "pr":

        # ----------------------------
        # Validate input mode
        # ----------------------------
        if not args.sarif and not args.findings and not args.provider:
            parser.error("You must provide one of: --sarif, --findings or --provider")

        # ----------------------------
        # Load findings
        # ----------------------------
        if args.sarif:

            from secscore.normalizers.sarif import normalize_sarif

            sarif_path = Path(args.sarif)

            if not sarif_path.exists():
                raise FileNotFoundError(f"SARIF file not found: {args.sarif}")

            print(f"Using SARIF input: {args.sarif}")

            findings = normalize_sarif(args.sarif)

        elif args.provider == "checkmarx":

            from secscore.adapters.checkmarx_provider import fetch_findings

            if not args.branch:
                args.branch = "main"

            print("Fetching findings from Checkmarx API")

            findings = fetch_findings(args)

        else:

            findings_path = Path(args.findings)

            if not findings_path.exists():
                raise FileNotFoundError(f"Findings file not found: {args.findings}")

            print(f"Using findings file: {args.findings}")

            findings = json.loads(findings_path.read_text(encoding="utf-8"))

        # ----------------------------
        # Load policy
        # ----------------------------
        policy = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))

        # ----------------------------
        # Run engine
        # ----------------------------
        result = run_engine(EngineInput(findings=findings, policy=policy, mode="pull_request"))

        # ----------------------------
        # Generate markdown
        # ----------------------------
        md = render_pr_comment(result)
        Path(args.out).write_text(md, encoding="utf-8")

        # ----------------------------
        # JSON result
        # ----------------------------
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

        print(md)

        return EXIT[result.decision]

    return 3

if __name__ == "__main__":
    raise SystemExit(main())