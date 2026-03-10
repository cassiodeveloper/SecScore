from __future__ import annotations

from typing import Any, Dict, List, Optional

from .engine import EngineResult


DEFAULT_MAX_FINDINGS = 5
DEFAULT_MAX_REASONS = 3


def _get(d: Dict[str, Any], path: str) -> Optional[Any]:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _get_reporting_config(result: EngineResult):

    reporting = {}

    policy = getattr(result, "policy", None)

    if policy:
        reporting = policy.get("reporting", {})

    max_findings = reporting.get("max_findings_in_comment", DEFAULT_MAX_FINDINGS)
    max_reasons = reporting.get("max_reasons", DEFAULT_MAX_REASONS)
    include_fields = reporting.get("include_fields", None)

    return max_findings, max_reasons, include_fields

def format_decision(decision: str):

    styles = {
        "PASS": "**PASS**",
        "REVIEW": "**REVIEW**",
        "FAIL": "**FAIL**"
    }

    return styles.get(decision, decision)

def render_pr_comment(result: EngineResult, policy) -> str:

    emoji = {
        "PASS": "✅",
        "REVIEW": "🟡",
        "FAIL": "⛔"
    }.get(result.decision, "❔")

    decision_fmt = f"**{result.decision}**"

    max_findings, max_reasons, include_fields = _get_reporting_config(result)

    lines: List[str] = []

    lines.append("<!-- SECSCORE_COMMENT -->")
    lines.append(f"## {emoji} SecScore — {decision_fmt}")
    lines.append("")
    lines.append(f"Security score: **{result.score}/100**")
    lines.append("")

    if result.decision == "FAIL":
        lines.append(f"⛔ Merge **blocked** by security policy: `{policy}`")
    elif result.decision == "REVIEW":
        lines.append("🟡 Security review recommended.")
    else:
        lines.append("✅ No blocking security issues detected.")

    if result.findings_shown:

        summary = summarize_findings(result.findings_shown)

        if summary:
            lines.append("")
            lines.append(
                f"New vulnerabilities introduced: **{', '.join(summary)}**"
            )

    if result.reasons:

        lines.append("\n---")
        lines.append("### Why this decision")

        for r in result.reasons[:max_reasons]:
            lines.append(f"- {r}")

        remaining = len(result.reasons) - max_reasons
        if remaining > 0:
            lines.append(f"\n_+{remaining} more reasons not shown._")

    if result.findings_shown:

        lines.extend(render_security_diff(result.findings_shown))

        lines.append("\n---")
        lines.append("### Findings introduced in this PR")

        findings = result.findings_shown[:max_findings]

        for f in findings:
            lines.append(_render_finding_line(f, include_fields))

        remaining = len(result.findings_shown) - max_findings
        if remaining > 0:
            lines.append(f"\n_+{remaining} additional findings not shown._")

    lines.append("\n---")
    lines.append("SecScore — Security scoring that matters.")

    return "\n".join(lines)

def _render_finding_line(f: Dict[str, Any], include_fields: Optional[List[str]]) -> str:

    title = f.get("title", "Untitled")
    sev = f.get("severity", "info").upper()

    path = _get(f, "asset.path")
    line = _get(f, "asset.line")

    loc = ""

    if path and line:
        loc = f"[`{path}:{line}`](./{path}#L{line})"
    elif path:
        loc = f"`{path}`"

    extras = []

    cve = _get(f, "metadata.cve")
    pkg = _get(f, "metadata.package")
    img = _get(f, "metadata.image")

    if cve:
        extras.append(str(cve))

    if pkg:
        extras.append(str(pkg))

    if img:
        extras.append(str(img))

    extra_s = f" [{', '.join(extras)}]" if extras else ""

    if loc:
        return f"- **{sev}** — {title}  \n  {loc}{extra_s}"

    return f"- **{sev}** — {title}{extra_s}"

def compute_security_diff(findings):

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for f in findings:
        sev = f.get("severity", "").upper()

        if sev in counts:
            counts[sev] += 1

    return counts

def render_security_diff(findings):

    counts = compute_security_diff(findings)

    if all(v == 0 for v in counts.values()):
        return []

    lines = []
    lines.append("\n---")
    lines.append("### Security Diff")

    icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:

        val = counts[sev]

        if val == 0:
            lines.append(f"{icons[sev]} {sev.title()}: 0  ")
        else:
            lines.append(f"{icons[sev]} {sev.title()}: +{val}  ")

    return lines

def summarize_findings(findings):

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for f in findings:

        sev = str(f.get("severity", "")).strip().upper()

        if sev in counts:
            counts[sev] += 1

    parts = []

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev] > 0:

            count = counts[sev]

            label = sev.title()

            parts.append(f"{count} {label}")

    return parts