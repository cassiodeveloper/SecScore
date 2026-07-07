from __future__ import annotations

import html
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .engine import EngineResult


DEFAULT_MAX_FINDINGS = 5
DEFAULT_MAX_REASONS = 3

# Markdown-significant characters that must be neutralized when injecting
# untrusted scanner text (titles, paths, CVEs) into the PR comment, so a
# crafted finding cannot inject links, emphasis, code spans or inline HTML.
_MD_ESCAPE_RE = re.compile(r"([\\`*_\[\]<>|])")


def _md_escape(text: Any) -> str:
    """Backslash-escape Markdown control characters in untrusted inline text."""
    return _MD_ESCAPE_RE.sub(r"\\\1", str(text))


def _md_code(text: Any) -> str:
    """Sanitize text for use inside a code span (backticks cannot be escaped)."""
    return str(text).replace("`", "'")


def _url_encode_path(path: Any) -> str:
    """Percent-encode a path for a Markdown link target, keeping path separators.

    ``#`` is intentionally NOT in the safe set so a literal ``#`` in a filename
    is encoded instead of being parsed as the start of a URL fragment.
    """
    return quote(str(path), safe="/")


def _get(d: Dict[str, Any], path: str) -> Optional[Any]:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _field_enabled(include_fields: Optional[List[str]], name: str) -> bool:
    """A field is rendered when no include_fields filter is set, or it is listed."""
    return include_fields is None or name in include_fields


def _get_reporting_config(policy_config: Optional[Dict[str, Any]]):

    reporting = {}

    if isinstance(policy_config, dict):
        candidate = policy_config.get("reporting")
        if isinstance(candidate, dict):
            reporting = candidate

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

def render_pr_comment(result: EngineResult, policy, policy_config=None) -> str:

    emoji = {
        "PASS": "✅",
        "REVIEW": "🟡",
        "FAIL": "⛔"
    }.get(result.decision, "❔")

    decision_fmt = f"**{result.decision}**"

    max_findings, max_reasons, include_fields = _get_reporting_config(policy_config)

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

    title = _md_escape(f.get("title", "Untitled"))
    sev = str(f.get("severity", "info")).upper()

    path = _get(f, "asset.path")
    line = _get(f, "asset.line")

    loc = ""

    if _field_enabled(include_fields, "asset.path") and path:
        show_line = _field_enabled(include_fields, "asset.line") and line
        if show_line:
            href = f"./{_url_encode_path(path)}#L{line}"
            loc = f"[`{_md_code(f'{path}:{line}')}`]({href})"
        else:
            loc = f"`{_md_code(path)}`"

    extras = []

    cve = _get(f, "metadata.cve") if _field_enabled(include_fields, "metadata.cve") else None
    pkg = _get(f, "metadata.package") if _field_enabled(include_fields, "metadata.package") else None
    img = _get(f, "metadata.image") if _field_enabled(include_fields, "metadata.image") else None

    if cve:
        extras.append(_md_escape(cve))

    if pkg:
        extras.append(_md_escape(pkg))

    if img:
        extras.append(_md_escape(img))

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


def render_html_report(
    result_json: Dict[str, Any],
    json_path: str = "secscore-result.json",
    execution_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Render a self-contained HTML report from the standard JSON output."""

    data = json.dumps(result_json, ensure_ascii=False)
    escaped_json = (
        data.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    escaped_path = html.escape(json_path)
    escaped_href = html.escape(json_path, quote=True)
    generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    context_rows = _render_html_context_rows(execution_context or {})

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecScore Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f2;
      --panel: #ffffff;
      --ink: #1b1f24;
      --muted: #65717c;
      --line: #d9dfd2;
      --soft: #fbfcf8;
      --pass: #197a4d;
      --review: #b7791f;
      --fail: #b42318;
      --accent: #0f6b7a;
    }}
    [data-theme="dark"] {{
      color-scheme: dark;
      --bg: #111416;
      --panel: #1b2024;
      --ink: #f3f5ef;
      --muted: #a6b0b8;
      --line: #333b42;
      --soft: #22282d;
      --accent: #65c6d8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        linear-gradient(135deg, rgba(15, 107, 122, 0.10), transparent 34%),
        linear-gradient(315deg, rgba(183, 121, 31, 0.13), transparent 28%),
        var(--bg);
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0;
    }}
    header {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 24px;
      align-items: end;
      margin-bottom: 20px;
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(30px, 5vw, 58px); line-height: 0.95; letter-spacing: 0; }}
    h2 {{ font-size: 16px; margin-bottom: 12px; }}
    .subtitle {{ color: var(--muted); margin-top: 10px; max-width: 660px; }}
    .source {{ color: var(--muted); font-size: 13px; text-align: right; }}
    .source a {{ color: var(--accent); font-weight: 700; text-decoration: none; }}
    .source a:hover {{ text-decoration: underline; }}
    .source button {{
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 5px 10px;
      color: var(--ink);
      background: var(--panel);
      font: inherit;
      font-size: 12px;
      cursor: pointer;
    }}
    .top-actions {{
      display: flex;
      justify-content: flex-end;
      margin-bottom: 18px;
    }}
    .theme-toggle {{
      display: inline-grid;
      grid-template-columns: auto auto;
      gap: 8px;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px;
      background: var(--panel);
      box-shadow: 0 10px 24px rgba(27, 31, 36, 0.08);
    }}
    .theme-toggle button {{
      border: 0;
      border-radius: 999px;
      padding: 7px 12px;
      color: var(--muted);
      background: transparent;
      font: inherit;
      font-size: 13px;
      cursor: pointer;
    }}
    .theme-toggle button[aria-pressed="true"] {{
      color: var(--decision-ink);
      background: var(--decision-color);
      font-weight: 700;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1.05fr 0.95fr;
      gap: 16px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 18px 45px rgba(27, 31, 36, 0.08);
    }}
    .hero {{
      min-height: 300px;
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      gap: 20px;
      align-items: center;
    }}
    .score-ring {{
      width: 220px;
      aspect-ratio: 1;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: conic-gradient(var(--decision-color) calc(var(--score) * 1%), #e7ebdf 0);
      position: relative;
    }}
    .score-ring::after {{
      content: "";
      position: absolute;
      inset: 18px;
      border-radius: 50%;
      background: var(--panel);
      border: 1px solid var(--line);
    }}
    .score-value {{
      position: relative;
      z-index: 1;
      text-align: center;
    }}
    .score-value strong {{ display: block; font-size: 56px; line-height: 1; }}
    .score-value span {{ color: var(--muted); font-size: 13px; }}
    .decision {{
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 6px 12px;
      border-radius: 999px;
      color: var(--decision-ink);
      background: var(--decision-color);
      font-weight: 700;
      letter-spacing: 0.08em;
      font-size: 13px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-top: 20px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: var(--soft);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; font-size: 24px; margin-top: 4px; }}
    .risk-summary {{
      margin-top: 16px;
      color: var(--muted);
      max-width: 560px;
      line-height: 1.5;
    }}
    .reasons {{ display: grid; gap: 10px; }}
    .reason {{
      border-left: 4px solid var(--decision-color);
      padding: 10px 12px;
      background: var(--soft);
      border-radius: 6px;
    }}
    .bars {{ display: grid; gap: 12px; }}
    .bar-row {{
      display: grid;
      grid-template-columns: 80px 1fr 42px;
      gap: 10px;
      align-items: center;
      font-size: 13px;
    }}
    .track {{
      height: 10px;
      border-radius: 999px;
      background: #e7ebdf;
      overflow: hidden;
    }}
    .fill {{ height: 100%; width: var(--value); background: var(--bar-color); }}
    .findings {{
      grid-column: 1 / -1;
    }}
    .context {{
      grid-column: 1 / -1;
    }}
    details.context {{
      display: block;
    }}
    details.context > summary {{
      cursor: pointer;
      font-weight: 700;
      margin-bottom: 12px;
    }}
    details.context > summary::marker {{
      color: var(--accent);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .sev {{
      display: inline-block;
      min-width: 76px;
      text-align: center;
      border-radius: 999px;
      padding: 4px 8px;
      color: white;
      font-size: 12px;
      font-weight: 700;
    }}
    .empty {{
      color: var(--muted);
      padding: 18px;
      background: var(--soft);
      border: 1px dashed var(--line);
      border-radius: 8px;
    }}
    footer {{
      width: min(1120px, calc(100% - 32px));
      margin: 20px auto 0;
      padding: 18px 0 32px;
      color: var(--muted);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      border-top: 1px solid var(--line);
      font-size: 13px;
    }}
    footer a {{ color: var(--accent); font-weight: 700; text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}
    @media (max-width: 820px) {{
      header, .grid, .hero {{ grid-template-columns: 1fr; }}
      .source {{ text-align: left; }}
      .score-ring {{ width: min(220px, 100%); justify-self: center; }}
      .metrics {{ grid-template-columns: 1fr; }}
      table {{ display: block; overflow-x: auto; }}
      .top-actions {{ justify-content: flex-start; }}
      footer {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="top-actions" aria-label="Theme">
      <div class="theme-toggle">
        <button type="button" id="lightTheme" aria-pressed="true">Light</button>
        <button type="button" id="darkTheme" aria-pressed="false">Dark</button>
      </div>
    </div>
    <header>
      <div>
        <h1>SecScore Report</h1>
        <p class="subtitle">Visual summary generated from the standard SecScore JSON output.</p>
      </div>
      <p class="source">
        Source JSON<br>
        <a href="{escaped_href}" id="jsonPath">{escaped_path}</a><br>
        <button type="button" id="copyJsonPath">Copy JSON path</button>
      </p>
    </header>

    <section class="grid">
      <div class="panel hero">
        <div class="score-ring" id="scoreRing">
          <div class="score-value">
            <strong id="score">0</strong>
            <span>security score</span>
          </div>
        </div>
        <div>
          <span class="decision" id="decision">UNKNOWN</span>
          <div class="metrics">
            <div class="metric"><span>New findings</span><strong id="newCount">0</strong></div>
            <div class="metric"><span>Shown findings</span><strong id="shownCount">0</strong></div>
            <div class="metric"><span>Penalty total</span><strong id="penalty">0</strong></div>
          </div>
          <p class="risk-summary" id="riskSummary"></p>
        </div>
      </div>

      <div class="panel">
        <h2>Decision Drivers</h2>
        <div class="reasons" id="reasons"></div>
      </div>

      <div class="panel">
        <h2>Severity Mix</h2>
        <div class="bars" id="severityBars"></div>
      </div>

      <div class="panel">
        <h2>Hard Fails</h2>
        <div id="hardFails"></div>
      </div>

      <div class="panel findings">
        <h2>Findings</h2>
        <div id="findings"></div>
      </div>

      <details class="panel context" open>
        <summary>Execution Parameters</summary>
        <table>
          <tbody>
            {context_rows}
          </tbody>
        </table>
      </details>
    </section>
  </main>
  <footer>
    <span><a href="https://secscore.dev">SecScore.dev</a></span>
    <span><strong>Report generated at:</strong> {generated_at}</span>
  </footer>

  <script type="application/json" id="secscore-data">{escaped_json}</script>
  <script>
    const data = JSON.parse(document.getElementById("secscore-data").textContent);
    const colors = {{
      low: "#1f8a4c",
      medium: "#f2c94c",
      high: "#ef6f6c",
      critical: "#8b1e1e",
      info: "#1f7fbf"
    }};
    const colorText = {{
      low: "#ffffff",
      medium: "#1b1f24",
      high: "#1b1f24",
      critical: "#ffffff",
      info: "#ffffff"
    }};
    const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({{
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "\\"": "&quot;", "'": "&#39;"
    }}[ch]));
    const setTheme = (theme) => {{
      document.documentElement.dataset.theme = theme;
      document.getElementById("lightTheme").setAttribute("aria-pressed", String(theme === "light"));
      document.getElementById("darkTheme").setAttribute("aria-pressed", String(theme === "dark"));
      localStorage.setItem("secscore-theme", theme);
    }};
    document.getElementById("lightTheme").addEventListener("click", () => setTheme("light"));
    document.getElementById("darkTheme").addEventListener("click", () => setTheme("dark"));
    setTheme(localStorage.getItem("secscore-theme") || "light");
    document.getElementById("copyJsonPath").addEventListener("click", async () => {{
      const path = document.getElementById("jsonPath").textContent;
      try {{
        await navigator.clipboard.writeText(path);
        document.getElementById("copyJsonPath").textContent = "Copied";
        setTimeout(() => document.getElementById("copyJsonPath").textContent = "Copy JSON path", 1400);
      }} catch {{
        document.getElementById("copyJsonPath").textContent = "Copy unavailable";
      }}
    }});
    const compactNumber = (value, maxLength = 6) => {{
      const numeric = Number(value ?? 0);
      if (!Number.isFinite(numeric)) return "0";
      const text = String(numeric);
      if (text.length <= maxLength) return text;
      if (Math.abs(numeric) >= 100000) return text.slice(0, maxLength);
      const integerLength = String(Math.trunc(Math.abs(numeric))).length + (numeric < 0 ? 1 : 0);
      const decimals = Math.max(0, maxLength - integerLength - 1);
      return numeric.toFixed(decimals).slice(0, maxLength);
    }};
    const decision = String(data.decision || "UNKNOWN").toUpperCase();
    const findings = Array.isArray(data.findings_shown) ? data.findings_shown : [];
    const counts = findings.reduce((acc, finding) => {{
      const sev = String(finding.severity || "info").toLowerCase();
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    }}, {{ critical: 0, high: 0, medium: 0, low: 0, info: 0 }});
    const hardFails = Array.isArray(data.hard_fails) ? data.hard_fails : [];
    const statusRisk = (() => {{
      if (decision === "PASS") return "low";
      if (decision === "REVIEW") return "medium";
      if (decision === "FAIL") return hardFails.length || counts.critical ? "critical" : "high";
      return counts.critical ? "critical" : counts.high ? "high" : counts.medium ? "medium" : counts.low ? "low" : "info";
    }})();
    document.documentElement.style.setProperty("--decision-color", colors[statusRisk] || colors.info);
    document.documentElement.style.setProperty("--decision-ink", colorText[statusRisk] || "#ffffff");
    document.documentElement.style.setProperty("--score", Math.max(0, Math.min(100, Number(data.score || 0))));
    document.getElementById("score").textContent = data.score ?? 0;
    document.getElementById("decision").textContent = decision;
    document.getElementById("newCount").textContent = data.findings_new_count ?? 0;
    document.getElementById("shownCount").textContent = data.findings_shown_count ?? 0;
    document.getElementById("penalty").textContent = compactNumber(data.penalties_total);
    const topSeverity = counts.critical ? "critical" : counts.high ? "high" : counts.medium ? "medium" : counts.low ? "low" : counts.info ? "info" : "";
    const topSeverityText = topSeverity ? `${{counts[topSeverity]}} ${{topSeverity}} finding${{counts[topSeverity] === 1 ? "" : "s"}}` : "no shown findings";
    const summaryByDecision = {{
      PASS: `This run passed with ${{topSeverityText}} in the displayed result set.`,
      REVIEW: `This run requires review due to ${{topSeverityText}}.`,
      FAIL: hardFails.length
        ? `This run failed because ${{hardFails.length}} hard-fail rule${{hardFails.length === 1 ? "" : "s"}} triggered.`
        : `This run failed due to ${{topSeverityText}}.`
    }};
    document.getElementById("riskSummary").textContent = summaryByDecision[decision] || `This run completed with decision ${{decision}}.`;

    const reasons = Array.isArray(data.reasons) ? data.reasons : [];
    document.getElementById("reasons").innerHTML = reasons.length
      ? reasons.map((reason) => `<div class="reason">${{esc(reason)}}</div>`).join("")
      : `<div class="empty">No decision drivers reported.</div>`;

    const max = Math.max(1, ...Object.values(counts));
    document.getElementById("severityBars").innerHTML = ["low", "medium", "high", "critical", "info"].map((sev) => `
      <div class="bar-row">
        <strong>${{sev.toUpperCase()}}</strong>
        <div class="track"><div class="fill" style="--value: ${{(counts[sev] / max) * 100}}%; --bar-color: ${{colors[sev]}}"></div></div>
        <span>${{counts[sev]}}</span>
      </div>
    `).join("");

    document.getElementById("hardFails").innerHTML = hardFails.length
      ? hardFails.map((item) => `<div class="reason"><strong>${{esc(item.rule_id)}}</strong><br>${{esc(item.reason)}}</div>`).join("")
      : `<div class="empty">No hard fail rules triggered.</div>`;

    document.getElementById("findings").innerHTML = findings.length
      ? `<table>
          <thead><tr><th>Severity</th><th>Title</th><th>Location</th></tr></thead>
          <tbody>${{findings.map((finding) => {{
            const sev = String(finding.severity || "info").toLowerCase();
            const asset = finding.asset || {{}};
            const location = asset.path ? `${{asset.path}}${{asset.line ? ":" + asset.line : ""}}` : "";
            const locationHref = asset.path ? `./${{asset.path}}${{asset.line ? "#L" + asset.line : ""}}` : "";
            const locationHtml = locationHref ? `<a href="${{esc(locationHref)}}">${{esc(location)}}</a>` : esc(location);
            return `<tr>
              <td><span class="sev" style="background: ${{colors[sev] || colors.info}}; color: ${{colorText[sev] || "#ffffff"}}">${{esc(sev.toUpperCase())}}</span></td>
              <td>${{esc(finding.title || "Untitled")}}</td>
              <td>${{locationHtml}}</td>
            </tr>`;
          }}).join("")}}</tbody>
        </table>`
      : `<div class="empty">No findings are included in the JSON report.</div>`;
  </script>
</body>
</html>
"""


def _render_html_context_rows(execution_context: Dict[str, Any]) -> str:
    linkable_keys = {"Input policy", "Effective policy", "JSON output", "HTML output"}
    rows = []
    for key, value in execution_context.items():
        if value is None:
            continue
        if isinstance(value, bool):
            display_value = "enabled" if value else "disabled"
        elif isinstance(value, (list, tuple)):
            display_value = ", ".join(str(item) for item in value if item is not None)
        else:
            display_value = str(value)

        if not display_value:
            continue

        escaped_key = html.escape(str(key))
        if str(key) in linkable_keys:
            href = display_value.replace("\\", "/")
            escaped_href = html.escape(href, quote=True)
            value_html = f'<a href="{escaped_href}">{html.escape(display_value)}</a>'
        else:
            value_html = html.escape(display_value)

        rows.append("<tr>" f"<th>{escaped_key}</th>" f"<td>{value_html}</td>" "</tr>")

    if not rows:
        return '<tr><td colspan="2" class="empty">No execution parameters were provided.</td></tr>'

    return "\n".join(rows)
