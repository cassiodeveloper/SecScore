"""
secscore/cli/main.py
"""
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
from secscore.core.policy_validator import validate_policy, PolicyValidationError

EXIT = {"PASS": 0, "REVIEW": 1, "FAIL": 2}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secscore",
        description="SecScore - Security Score that matters."
    )

    sub = parser.add_subparsers(dest="cmd", required=True)
    pr  = sub.add_parser("pr", help="Run SecScore for Pull Requests (PR mode)")

    pr.add_argument("--findings", help="Path to findings.json")
    pr.add_argument(
        "--sarif",
        action="append",
        help="Path to SARIF file. Can be specified multiple times or as comma-separated list.",
    )
    pr.add_argument(
        "--no-diff-aware",
        dest="no_diff_aware",
        action="store_true",
        default=False,
        help="Disable diff-aware filtering (enabled by default in PR mode).",
    )
    pr.add_argument("--base-ref", dest="base_ref", default="origin/main",
                    help="Git ref to diff against (default: origin/main).")
    pr.add_argument("--policy",   required=True, help="Path to policy YAML")
    pr.add_argument("--out",      default="pr-comment.md",        help="Output PR comment markdown")
    pr.add_argument("--json-out", default="secscore-result.json", help="Output JSON result")

    # provider
    pr.add_argument("--provider")
    pr.add_argument("--checkmarx-project")
    pr.add_argument("--checkmarx-base-url")
    pr.add_argument("--checkmarx-token")
    pr.add_argument("--branch")
    pr.add_argument("--checkmarx-tenant")

    args = parser.parse_args()

    if args.cmd == "pr":
        console = Console()

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

            sarif_paths = []
            for entry in args.sarif:
                for p in entry.split(","):
                    p = p.strip()
                    if p:
                        sarif_paths.append(p)

            missing = [p for p in sarif_paths if not Path(p).exists()]
            if missing:
                for m in missing:
                    console.print(f"[bold red]SARIF file not found:[/bold red] {m}")
                return 2

            if len(sarif_paths) == 1:
                console.print(f"[cyan]Using SARIF input:[/cyan] {sarif_paths[0]}")
            else:
                console.print(f"[cyan]Using {len(sarif_paths)} SARIF files:[/cyan] {', '.join(sarif_paths)}")

            findings = normalize_sarif(sarif_paths)

        elif args.provider == "checkmarx":
            from secscore.adapters.checkmarx_provider import fetch_findings
            if not args.branch:
                args.branch = "main"
            console.print("[cyan]Fetching findings from Checkmarx API...[/cyan]")
            findings = fetch_findings(args)

        else:
            findings_path = Path(args.findings)
            if not findings_path.exists():
                raise FileNotFoundError(f"Findings file not found: {args.findings}")
            console.print(f"[cyan]Using findings file:[/cyan] {args.findings}")
            findings = json.loads(findings_path.read_text(encoding="utf-8"))

        # ----------------------------
        # Diff-aware (v0.3.0: ativo por padrão)
        # ----------------------------
        if not args.no_diff_aware:
            findings = _apply_diff_aware(findings, args.base_ref, console)
        else:
            console.print("[yellow]Diff-aware filtering disabled.[/yellow]")

        # ----------------------------
        # Load & validate policy
        # ----------------------------
        policy = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))

        try:
            validate_policy(policy)
        except PolicyValidationError as exc:
            console.print(f"[bold red]Erro na policy:[/bold red] {args.policy}")
            for err in exc.errors:
                console.print(f"  [red]•[/red] {err}")
            return 2

        # ----------------------------
        # Run engine
        # ----------------------------
        result = run_engine(EngineInput(findings=findings, policy=policy, mode="pull_request"))

        # ----------------------------
        # Outputs
        # ----------------------------
        md = render_pr_comment(result, policy=args.policy)
        Path(args.out).write_text(md, encoding="utf-8")

        out_json = {
            "score":                result.score,
            "decision":             result.decision,
            "reasons":              result.reasons,
            "hard_fails":           [hf.__dict__ for hf in result.hard_fails],
            "penalties_total":      result.penalties_total,
            "findings_new_count":   len(result.findings_new),
            "findings_shown_count": len(result.findings_shown),
        }
        Path(args.json_out).write_text(json.dumps(out_json, indent=2), encoding="utf-8")

        render_terminal(result, md)

        return EXIT[result.decision]

    return 3


def _apply_diff_aware(findings, base_ref: str, console) -> dict:
    """
    Aplica diff-aware filtering.

    Regras de segurança para não descartar findings por engano:
    - Se git falhar (não é repo, sem remote): skip silencioso, findings intactos.
    - Se changed_ranges vier vazio (branch sem commits, diff limpo): skip,
      findings intactos. Um diff vazio não significa "nada mudou no PR" —
      pode significar que o histórico não foi carregado (shallow clone).
    - Só filtra quando changed_ranges tem ao menos um arquivo.
    """
    from secscore.core.diff_filter import get_changed_ranges, filter_findings_by_diff

    try:
        changed_ranges = get_changed_ranges(base_ref)
    except Exception as exc:
        console.print(
            f"[yellow]Warning:[/yellow] diff-aware skipped — could not run git diff ({exc}). "
            "Use --no-diff-aware to suppress. All findings will be evaluated."
        )
        return findings

    if not changed_ranges:
        console.print(
            "[yellow]Warning:[/yellow] diff-aware skipped — no changed files detected "
            f"against '{base_ref}'. All findings will be evaluated. "
            "Tip: ensure fetch-depth: 0 in your checkout step, or use --no-diff-aware."
        )
        return findings

    # Só filtra quando há dados confiáveis do diff
    console.print(f"[cyan]Diff-aware:[/cyan] {len(changed_ranges)} changed file(s) detected.")

    if isinstance(findings, dict):
        original = len(findings.get("findings", []))
        findings["findings"] = filter_findings_by_diff(findings["findings"], changed_ranges)
        filtered = len(findings["findings"])
    else:
        original = len(findings)
        findings = filter_findings_by_diff(findings, changed_ranges)
        filtered = len(findings)

    console.print(f"[cyan]Diff-aware:[/cyan] {original} findings → {filtered} after filter.")
    return findings


def render_terminal(result, md):
    console = Console()

    emoji = {"PASS": "✅", "REVIEW": "🟡", "FAIL": "⛔"}.get(result.decision, "❔")

    console.print(Panel(
        f"[bold]Decision:[/bold] {result.decision}\n"
        f"[bold]Score:[/bold] {result.score}/100\n"
        f"[bold]Findings (new):[/bold] {len(result.findings_new)}",
        title=f"{emoji} SecScore Result",
        border_style="cyan",
    ))

    if result.findings_shown:
        table = Table(title="Findings introduced in this PR")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Location")

        colors = {
            "CRITICAL": "[red]CRITICAL[/red]",
            "HIGH":     "[orange3]HIGH[/orange3]",
            "MEDIUM":   "[yellow]MEDIUM[/yellow]",
            "LOW":      "[green]LOW[/green]",
        }

        for f in result.findings_shown[:5]:
            sev   = colors.get(f.get("severity", "").upper(), f.get("severity", "").upper())
            title = f.get("title", "")
            path  = f.get("asset", {}).get("path")
            line  = f.get("asset", {}).get("line")
            loc   = f"{path}:{line}" if path and line else (path or "")
            table.add_row(sev, title, loc)

        console.print(table)

    console.print(Panel(Markdown(md), title="PR Comment Preview", border_style="green"))

if __name__ == "__main__":
    raise SystemExit(main())