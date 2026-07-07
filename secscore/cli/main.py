"""
secscore/cli/main.py
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from secscore.core.engine import EngineInput, run_engine
from secscore.core.policy_validator import PolicyValidationError, validate_policy
from secscore.core.reporting import render_html_report, render_pr_comment

EXIT = {"PASS": 0, "REVIEW": 1, "FAIL": 2}


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _allowed_path_roots(include_ci_roots: bool = False) -> list[Path]:
    roots = [Path.cwd().resolve()]
    if include_ci_roots:
        for env_name in ("GITHUB_WORKSPACE", "RUNNER_TEMP"):
            value = os.getenv(env_name)
            if value:
                try:
                    roots.append(Path(value).expanduser().resolve())
                except Exception:
                    continue
    return roots


def _resolve_cli_path(
    value: str,
    label: str,
    *,
    must_exist: bool = False,
    for_output: bool = False,
    include_ci_roots: bool = False,
) -> Path:
    if not value or not str(value).strip():
        raise ValueError(f"{label} path is required")

    base_dir = Path.cwd().resolve()
    raw_path = Path(str(value).strip()).expanduser()
    candidate = raw_path if raw_path.is_absolute() else base_dir / raw_path

    if for_output:
        resolved_parent = candidate.parent.resolve()
        resolved = resolved_parent / candidate.name
    else:
        resolved = candidate.resolve(strict=must_exist)

    roots = _allowed_path_roots(include_ci_roots=include_ci_roots)
    if not any(_is_within(resolved, root) or resolved == root for root in roots):
        allowed = ", ".join(str(root) for root in roots)
        raise ValueError(f"{label} path must resolve inside an allowed directory: {allowed}")

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"{label} file not found: {value}")
    if for_output and not resolved.parent.exists():
        raise FileNotFoundError(f"{label} output directory not found: {resolved.parent}")

    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secscore",
        description="SecScore - Security Score that matters.",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("pr", help="Run SecScore for Pull Requests (PR mode)")

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
    pr.add_argument(
        "--base-ref",
        dest="base_ref",
        default="origin/main",
        help="Git ref to diff against (default: origin/main).",
    )
    pr.add_argument("--policy", required=True, help="Path to policy YAML")
    pr.add_argument("--out", default="pr-comment.md", help="Output PR comment markdown")
    pr.add_argument("--json-out", default="secscore-result.json", help="Output JSON result")
    pr.add_argument(
        "--html-output",
        choices=["true", "false"],
        default="false",
        help="Set to true to generate a visual HTML report from the standard JSON result.",
    )
    pr.add_argument("--html-out", default="secscore-report.html", help="Output HTML report")

    # provider
    pr.add_argument("--provider")
    pr.add_argument("--checkmarx-project")
    pr.add_argument("--checkmarx-base-url")
    pr.add_argument("--checkmarx-token")
    pr.add_argument("--branch")
    pr.add_argument("--checkmarx-tenant")

    # M.A.R.I.A integration
    pr.add_argument(
        "--token",
        help="Generic bearer token accepted by integrations (used by M.A.R.I.A integration).",
    )
    pr.add_argument("--maria-url", help="M.A.R.I.A API endpoint URL to receive consolidated findings.")
    pr.add_argument("--maria-token", help="M.A.R.I.A API bearer token (overrides --token).")
    pr.add_argument(
        "--maria-import-policy",
        choices=["true", "false"],
        help=(
            "Import risk policy from M.A.R.I.A on each run. "
            "Defaults to true when integrated, false otherwise."
        ),
    )
    pr.add_argument("--maria-policy-url", help="Optional explicit M.A.R.I.A policy endpoint URL.")
    pr.add_argument(
        "--maria-repository-id",
        help="M.A.R.I.A repository id (GUID). Required for submissions endpoint and policy import.",
    )
    pr.add_argument("--maria-submission-key", help="M.A.R.I.A submission key. Auto-generated when omitted.")
    pr.add_argument("--maria-commit-sha", help="Commit SHA for M.A.R.I.A submission.")
    pr.add_argument("--maria-branch-name", help="Branch name for M.A.R.I.A submission.")
    pr.add_argument("--maria-pipeline-name", help="Pipeline name for M.A.R.I.A submission.")
    pr.add_argument("--maria-pipeline-run-id", help="Pipeline run id for M.A.R.I.A submission.")
    pr.add_argument("--maria-pull-request-id", help="Pull request id for M.A.R.I.A submission.")
    pr.add_argument("--maria-started-at-utc", help="Pipeline start datetime in UTC (ISO-8601).")
    pr.add_argument("--maria-tool-name", help="Tool name for M.A.R.I.A submission.")
    pr.add_argument("--maria-cli-version", help="SecScore CLI version for M.A.R.I.A submission.")
    pr.add_argument(
        "--maria-timeout",
        type=int,
        default=15,
        help="Timeout in seconds for M.A.R.I.A API request (default: 15).",
    )
    pr.add_argument(
        "--maria-strict",
        action="store_true",
        default=False,
        help="Fail SecScore execution when sending findings to M.A.R.I.A fails.",
    )

    args = parser.parse_args()

    if args.cmd != "pr":
        return 3

    console = Console()

    # ----------------------------
    # Validate input mode
    # ----------------------------
    if not args.sarif and not args.findings and not args.provider:
        parser.error("You must provide one of: --sarif, --findings or --provider")

    maria_token = args.maria_token or args.token
    is_maria_integrated = bool(args.maria_url and maria_token and args.maria_repository_id)

    if args.maria_url and not maria_token:
        parser.error("When using --maria-url you must provide --maria-token or --token")
    if args.maria_url and not args.maria_repository_id:
        parser.error("When using --maria-url you must provide --maria-repository-id (GUID)")

    if args.maria_import_policy is None:
        use_maria_policy = is_maria_integrated
    else:
        use_maria_policy = args.maria_import_policy == "true"

    if use_maria_policy and not is_maria_integrated:
        parser.error(
            "M.A.R.I.A policy import requires integration: --maria-url, "
            "--maria-repository-id and --token/--maria-token"
        )

    # ----------------------------
    # Load findings
    # ----------------------------
    input_mode = "unknown"
    input_paths: list[str] = []
    if args.sarif:
        from secscore.normalizers.sarif import normalize_sarif

        sarif_paths: list[str] = []
        for entry in args.sarif:
            for part in entry.split(","):
                path = part.strip()
                if path:
                    try:
                        sarif_paths.append(str(_resolve_cli_path(path, "SARIF", must_exist=True)))
                    except Exception as exc:
                        console.print(f"[bold red]Invalid SARIF path:[/bold red] {path} ({exc})")
                        return 2

        if len(sarif_paths) == 1:
            console.print(f"[cyan]Using SARIF input:[/cyan] {sarif_paths[0]}")
        else:
            console.print(f"[cyan]Using {len(sarif_paths)} SARIF files:[/cyan] {', '.join(sarif_paths)}")

        input_mode = "sarif"
        input_paths = sarif_paths
        findings = normalize_sarif(sarif_paths)

    elif args.provider == "checkmarx":
        from secscore.adapters.checkmarx_provider import fetch_findings

        if not args.branch:
            args.branch = "main"

        console.print("[cyan]Fetching findings from Checkmarx API...[/cyan]")
        input_mode = "provider"
        input_paths = [args.provider]
        findings = fetch_findings(args)

    else:
        try:
            findings_path = _resolve_cli_path(args.findings, "Findings", must_exist=True)
        except Exception as exc:
            console.print(f"[bold red]Invalid findings path:[/bold red] {args.findings} ({exc})")
            return 2
        console.print(f"[cyan]Using findings file:[/cyan] {args.findings}")
        input_mode = "findings"
        input_paths = [str(findings_path)]
        findings = json.loads(findings_path.read_text(encoding="utf-8"))

    # Preserve consolidated payload before PR-specific filtering so
    # M.A.R.I.A receives full parser/normalizer output.
    findings_for_maria = copy.deepcopy(findings)

    # ----------------------------
    # Diff-aware
    # ----------------------------
    if not args.no_diff_aware:
        findings = _apply_diff_aware(findings, args.base_ref, console)
    else:
        console.print("[yellow]Diff-aware filtering disabled.[/yellow]")

    # ----------------------------
    # Load/Sync & validate policy
    # ----------------------------
    try:
        effective_policy_path = _resolve_cli_path(args.policy, "Policy", must_exist=True)
    except Exception as exc:
        console.print(f"[bold red]Invalid policy path:[/bold red] {args.policy} ({exc})")
        return 2

    try:
        base_policy = yaml.safe_load(effective_policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[bold red]Failed to load policy file:[/bold red] {args.policy} ({exc})")
        return 2

    policy = base_policy
    if use_maria_policy:
        from secscore.adapters.maria_provider import (
            build_secscore_policy_from_maria,
            fetch_policy,
        )

        console.print("[cyan]Syncing policy from M.A.R.I.A...[/cyan]")
        try:
            maria_policy = fetch_policy(
                maria_url=args.maria_url,
                token=maria_token,
                repository_id=args.maria_repository_id,
                timeout=args.maria_timeout,
                policy_url=args.maria_policy_url,
            )
            policy = build_secscore_policy_from_maria(maria_policy, base_policy)

            policy_dir = _resolve_cli_path("policy", "Policy output directory")
            policy_dir.mkdir(parents=True, exist_ok=True)
            effective_policy_path = policy_dir / "policy-maria.yml"
            effective_policy_path.write_text(
                yaml.safe_dump(policy, sort_keys=False),
                encoding="utf-8",
            )
            console.print(f"[green]M.A.R.I.A policy synced:[/green] {effective_policy_path}")
        except Exception as exc:
            console.print(f"[bold red]Failed to sync policy from M.A.R.I.A:[/bold red] {exc}")
            return 2

    try:
        validate_policy(policy)
    except PolicyValidationError as exc:
        console.print(f"[bold red]Policy validation error:[/bold red] {effective_policy_path}")
        for err in exc.errors:
            console.print(f"  [red]-[/red] {err}")
        return 2

    # ----------------------------
    # Run engine
    # ----------------------------
    result = run_engine(EngineInput(findings=findings, policy=policy, mode="pull_request"))

    # ----------------------------
    # Outputs
    # ----------------------------
    md = render_pr_comment(result, policy=str(effective_policy_path), policy_config=policy)
    try:
        output_path = _resolve_cli_path(args.out, "Markdown output", for_output=True)
        json_output_path = _resolve_cli_path(args.json_out, "JSON output", for_output=True)
    except Exception as exc:
        console.print(f"[bold red]Invalid output path:[/bold red] {exc}")
        return 2

    output_path.write_text(md, encoding="utf-8")

    out_json = {
        "score": result.score,
        "decision": result.decision,
        "reasons": result.reasons,
        "hard_fails": [hf.__dict__ for hf in result.hard_fails],
        "penalties_total": result.penalties_total,
        "findings_new_count": len(result.findings_new),
        "findings_shown_count": len(result.findings_shown),
        "findings_shown": result.findings_shown,
    }
    json_output_path.write_text(json.dumps(out_json, indent=2), encoding="utf-8")

    if args.html_output == "true":
        try:
            html_output_path = _resolve_cli_path(args.html_out, "HTML output", for_output=True)
        except Exception as exc:
            console.print(f"[bold red]Invalid HTML output path:[/bold red] {exc}")
            return 2

        execution_context = _build_execution_context(
            args=args,
            input_mode=input_mode,
            input_paths=input_paths,
            effective_policy_path=effective_policy_path,
            use_maria_policy=use_maria_policy,
            json_output_path=json_output_path,
            html_output_path=html_output_path,
        )
        html_report = render_html_report(
            out_json,
            json_path=str(json_output_path),
            execution_context=execution_context,
        )
        html_output_path.write_text(html_report, encoding="utf-8")
        console.print(f"[green]HTML report generated:[/green] {html_output_path}")

    if args.maria_url and maria_token:
        from secscore.adapters.maria_provider import send_submission

        console.print(f"[cyan]Sending consolidated findings to M.A.R.I.A:[/cyan] {args.maria_url}")
        try:
            submission_payload = _build_maria_submission_payload(args, result, findings_for_maria)
            send_submission(
                maria_url=args.maria_url,
                token=maria_token,
                submission_payload=submission_payload,
                timeout=args.maria_timeout,
            )
            console.print("[green]M.A.R.I.A integration:[/green] findings sent successfully.")
        except Exception as exc:
            console.print(f"[bold yellow]Warning:[/bold yellow] failed to send findings to M.A.R.I.A ({exc})")
            if args.maria_strict:
                return 2
    elif maria_token and not args.maria_url:
        console.print("[yellow]Warning:[/yellow] --token/--maria-token provided without --maria-url. Skipping M.A.R.I.A integration.")

    render_terminal(result, md)
    return EXIT[result.decision]


def _build_maria_submission_payload(args, result, findings_for_maria):
    commit_sha = _coalesce(
        args.maria_commit_sha,
        _env("GITHUB_SHA"),
        _git_value(["rev-parse", "HEAD"]),
        "unknown",
    )
    branch_name = _coalesce(
        args.maria_branch_name,
        args.branch,
        _env("GITHUB_HEAD_REF"),
        _env("GITHUB_REF_NAME"),
        _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
        "unknown",
    )
    pipeline_name = _coalesce(
        args.maria_pipeline_name,
        _env("GITHUB_WORKFLOW"),
        "secscore-cli",
    )
    pipeline_run_id = _coalesce(
        args.maria_pipeline_run_id,
        _env("GITHUB_RUN_ID"),
        datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
    )
    submission_key = _coalesce(
        args.maria_submission_key,
        f"{pipeline_name}-{pipeline_run_id}-{str(commit_sha)[:8]}",
    )

    pull_request_id = _coalesce(
        args.maria_pull_request_id,
        _env("SECSCORE_PULL_REQUEST_ID"),
        _env("GITHUB_EVENT_PULL_REQUEST_NUMBER"),
        _github_event_pull_request_number(),
        _env("CI_MERGE_REQUEST_IID"),
        _env("CI_MERGE_REQUEST_ID"),
        _env("SYSTEM_PULLREQUEST_PULLREQUESTID"),
        _env("BITBUCKET_PR_ID"),
    )
    started_at_utc = _coalesce(
        args.maria_started_at_utc,
        datetime.now(timezone.utc).isoformat(),
    )
    tool_name = _coalesce(
        args.maria_tool_name,
        "SecScore",
    )
    cli_version = _coalesce(
        args.maria_cli_version,
        _read_secscore_version(),
    )

    findings_list = findings_for_maria.get("findings", []) if isinstance(findings_for_maria, dict) else findings_for_maria

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in result.findings_new:
        sev = str(finding.get("severity", "")).strip().lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "SubmissionKey": submission_key,
        "RepositoryId": str(args.maria_repository_id),
        "CommitSha": str(commit_sha),
        "BranchName": str(branch_name),
        "Score": int(result.score),
        "Decision": str(result.decision).upper(),
        "PipelineName": str(pipeline_name),
        "PipelineRunId": str(pipeline_run_id),
        "PullRequestId": None if pull_request_id is None else str(pull_request_id),
        "StartedAtUtc": str(started_at_utc),
        "ToolName": None if tool_name is None else str(tool_name),
        "CliVersion": None if cli_version is None else str(cli_version),
        "Summary": {
            "Critical": severity_counts["critical"],
            "High": severity_counts["high"],
            "Medium": severity_counts["medium"],
            "Low": severity_counts["low"],
        },
        "Findings": findings_list,
    }


def _build_execution_context(
    args,
    input_mode: str,
    input_paths: list[str],
    effective_policy_path: Path,
    use_maria_policy: bool,
    json_output_path: Path | None = None,
    html_output_path: Path | None = None,
) -> dict:
    context = {
        "Command": "secscore pr",
        "SecScore version": _read_secscore_version(),
        "Input mode": input_mode,
        "Input": input_paths,
        "Input policy": str(args.policy),
        "Effective policy": str(effective_policy_path),
        "Diff-aware": not args.no_diff_aware,
        "Base ref": args.base_ref,
        "JSON output": str(json_output_path or args.json_out),
        "HTML output": str(html_output_path or args.html_out),
    }

    if args.provider:
        context["Provider"] = args.provider
    if args.branch:
        context["Branch"] = args.branch
    if args.checkmarx_project:
        context["Checkmarx project"] = args.checkmarx_project
    if args.checkmarx_base_url:
        context["Checkmarx base URL"] = _safe_url_display(args.checkmarx_base_url)
    if args.checkmarx_tenant:
        context["Checkmarx tenant"] = args.checkmarx_tenant

    context["M.A.R.I.A integration"] = bool(args.maria_url)
    if args.maria_url:
        context["M.A.R.I.A URL"] = _safe_url_display(args.maria_url)
    context["M.A.R.I.A policy import"] = use_maria_policy
    if args.maria_repository_id:
        context["M.A.R.I.A repository ID"] = args.maria_repository_id
    if args.maria_pull_request_id:
        context["Pull request ID"] = args.maria_pull_request_id
    if args.maria_commit_sha:
        context["Commit SHA"] = args.maria_commit_sha
    if args.maria_pipeline_name:
        context["Pipeline name"] = args.maria_pipeline_name
    if args.maria_pipeline_run_id:
        context["Pipeline run ID"] = args.maria_pipeline_run_id

    return context


def _safe_url_display(value: str) -> str:
    try:
        parts = urlsplit(value)
    except Exception:
        return value.split("?", 1)[0].split("#", 1)[0]

    if not parts.scheme or not parts.netloc:
        return value.split("?", 1)[0].split("#", 1)[0]

    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _coalesce(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _env(name: str):
    return os.getenv(name)


def _github_event_pull_request_number() -> str | None:
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path:
        return None

    try:
        resolved_event_path = _resolve_cli_path(
            event_path,
            "GitHub event",
            must_exist=True,
            include_ci_roots=True,
        )
        payload = json.loads(resolved_event_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    pull_request = payload.get("pull_request") if isinstance(payload, dict) else None
    if not isinstance(pull_request, dict):
        return None

    number = pull_request.get("number")
    return None if number is None else str(number)


def _git_value(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
        )
        value = completed.stdout.strip()
        return value or None
    except Exception:
        return None


def _read_secscore_version() -> str | None:
    try:
        from secscore import __version__  # type: ignore[attr-defined]

        return str(__version__)
    except Exception:
        return None


def _apply_diff_aware(findings, base_ref: str, console) -> dict:
    """
    Apply diff-aware filtering safely.

    Safety rules:
    - If git fails, skip filtering and keep findings.
    - If changed ranges are empty, skip filtering and keep findings.
    - Filter only when changed ranges contain at least one file.
    """
    from secscore.core.diff_filter import filter_findings_by_diff, get_changed_ranges

    try:
        changed_ranges = get_changed_ranges(base_ref)
    except Exception as exc:
        console.print(
            f"[yellow]Warning:[/yellow] diff-aware skipped - could not run git diff ({exc}). "
            "Use --no-diff-aware to suppress. All findings will be evaluated."
        )
        return findings

    if not changed_ranges:
        console.print(
            "[yellow]Warning:[/yellow] diff-aware skipped - no changed files detected "
            f"against '{base_ref}'. All findings will be evaluated. "
            "Tip: ensure fetch-depth: 0 in checkout, or use --no-diff-aware."
        )
        return findings

    console.print(f"[cyan]Diff-aware:[/cyan] {len(changed_ranges)} changed file(s) detected.")

    if isinstance(findings, dict):
        original = len(findings.get("findings", []))
        findings["findings"] = filter_findings_by_diff(findings["findings"], changed_ranges)
        filtered = len(findings["findings"])
    else:
        original = len(findings)
        findings = filter_findings_by_diff(findings, changed_ranges)
        filtered = len(findings)

    console.print(f"[cyan]Diff-aware:[/cyan] {original} findings -> {filtered} after filter.")
    return findings


def render_terminal(result, md):
    console = Console()

    emoji = {"PASS": "✅", "REVIEW": "🟡", "FAIL": "⛔"}.get(result.decision, "?")

    console.print(
        Panel(
            f"[bold]Decision:[/bold] {result.decision}\n"
            f"[bold]Score:[/bold] {result.score}/100\n"
            f"[bold]Findings (new):[/bold] {len(result.findings_new)}",
            title=f"{emoji} SecScore Result",
            border_style="cyan",
        )
    )

    if result.findings_shown:
        table = Table(title="Findings introduced in this PR")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Location")

        colors = {
            "CRITICAL": "[red]CRITICAL[/red]",
            "HIGH": "[orange3]HIGH[/orange3]",
            "MEDIUM": "[yellow]MEDIUM[/yellow]",
            "LOW": "[green]LOW[/green]",
        }

        for finding in result.findings_shown[:5]:
            sev = colors.get(finding.get("severity", "").upper(), finding.get("severity", "").upper())
            title = finding.get("title", "")
            path = finding.get("asset", {}).get("path")
            line = finding.get("asset", {}).get("line")
            loc = f"{path}:{line}" if path and line else (path or "")
            table.add_row(sev, title, loc)

        console.print(table)

    console.print(Panel(Markdown(md), title="PR Comment Preview", border_style="green"))


if __name__ == "__main__":
    raise SystemExit(main())
