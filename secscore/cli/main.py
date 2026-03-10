from __future__ import annotations

import argparse
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

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
    pr.add_argument("--diff_aware", default=False, help="Enable diff-aware filtering")
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

            console = Console()
            console.print(f"[cyan]Using SARIF input:[/cyan] {args.sarif}")

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
        # Diff filter
        # ----------------------------
        if args.diff_aware:

            from secscore.core.diff_filter import get_changed_ranges, filter_findings_by_diff

            changed_ranges = get_changed_ranges(args.base_ref)

            print(f"Changed files detected: {len(changed_ranges)}")

            if isinstance(findings, dict):
                original = len(findings.get("findings", []))
                findings["findings"] = filter_findings_by_diff(findings["findings"], changed_ranges)
                filtered = len(findings["findings"])
            else:
                original = len(findings)
                findings = filter_findings_by_diff(findings, changed_ranges)
                filtered = len(findings)

            print(f"Findings before filter: {original}")
            print(f"Findings after filter: {filtered}")

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
        md = render_pr_comment(result, policy=args.policy)
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

        render_terminal(result, md)

        return EXIT[result.decision]

    return 3

def render_terminal(result, md):

    console = Console()

    emoji = {
        "PASS": "✅",
        "REVIEW": "🟡",
        "FAIL": "⛔"
    }.get(result.decision, "❔")

    # ---------------------------
    # Result panel
    # ---------------------------
    console.print(Panel(f"[bold]Decision:[/bold] {result.decision}\n" f"[bold]Score:[/bold] {result.score}/100\n" f"[bold]Findings (new):[/bold] {len(result.findings_new)}", title=f"{emoji} SecScore Result", border_style="cyan"))

    # ---------------------------
    # Findings summary
    # ---------------------------
    if result.findings_shown:

        table = Table(title="Findings introduced in this PR")

        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Location")

        for f in result.findings_shown[:5]:

            sev = f.get("severity", "").upper()

            colors = {
                "CRITICAL": "[red]CRITICAL[/red]",
                "HIGH": "[orange3]HIGH[/orange3]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[green]LOW[/green]"
            }

            sev = colors.get(sev, sev)
            title = f.get("title", "")

            path = f.get("asset", {}).get("path")
            line = f.get("asset", {}).get("line")

            if path and line:
                loc = f"{path}:{line}"
            elif path:
                loc = path
            else:
                loc = ""

            table.add_row(sev, title, loc)

        console.print(table)

    # ---------------------------
    # Markdown preview
    # ---------------------------
    console.print(Panel(Markdown(md), title="PR Comment Preview", border_style="green"))

if __name__ == "__main__":
    raise SystemExit(main())