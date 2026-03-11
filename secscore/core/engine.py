"""
secscore/core/engine.py
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import json
import fnmatch

Decision = str  # "PASS" | "REVIEW" | "FAIL"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class EngineInput:
    findings: Dict[str, Any]
    policy:   Dict[str, Any]
    mode:     str = "pull_request"


@dataclass(frozen=True)
class HardFailHit:
    rule_id:             str
    reason:              str
    finding_fingerprint: str


@dataclass(frozen=True)
class EngineResult:
    score:           int
    decision:        Decision
    reasons:         List[str]
    hard_fails:      List[HardFailHit]
    findings_new:    List[Dict[str, Any]]
    findings_shown:  List[Dict[str, Any]]
    penalties_total: float


def run_engine(inp: EngineInput) -> EngineResult:
    policy = inp.policy

    if isinstance(inp.findings, list):
        findings_all = inp.findings
    else:
        findings_all = inp.findings.get("findings", [])

    ignore_patterns = inp.policy.get("ignore_paths", [])

    # Filtrar por ignore_paths
    filtered_findings = []
    for f in findings_all:
        asset = f.get("asset", {})
        # FIX: path pode ser None
        path = (asset.get("path") or "").replace("\\", "/")
        if should_ignore_path(path, ignore_patterns):
            continue
        filtered_findings.append(f)

    findings_all = filtered_findings

    # 1) Apenas findings novos (PR mode)
    findings_new = [f for f in findings_all if bool(f.get("is_new", False))]

    # 2) Supressões (tags, rule_ids e fingerprints)
    suppressions = policy.get("suppressions") or {}
    findings_new = [f for f in findings_new if not _is_suppressed(f, suppressions)]

    # 3) Hard-fails
    hard_fails = _evaluate_hard_fails(findings_new, policy)

    # 4) Score
    base_score      = int(policy["scoring"]["base_score"])
    penalties_total = sum(_score_finding(f, policy) for f in findings_new)
    score           = max(0, int(round(base_score - penalties_total)))

    # 5) Decisão
    decision = _decide(score, hard_fails, policy)

    # 6) Reasons
    reasons = _build_reasons(findings_new, hard_fails, policy)

    # 7) Findings para o comentário
    findings_shown = _select_findings_to_show(findings_new, hard_fails, policy)

    return EngineResult(
        score=score,
        decision=decision,
        reasons=reasons,
        hard_fails=hard_fails,
        findings_new=findings_new,
        findings_shown=findings_shown,
        penalties_total=float(penalties_total),
    )


# ---------------------------------------------------------------------------
# Supressões
# ---------------------------------------------------------------------------

def _is_suppressed(f: Dict[str, Any], suppressions: Dict[str, Any]) -> bool:
    meta        = f.get("metadata") or {}
    tags        = meta.get("tags") or []
    rule_id     = meta.get("rule_id")
    fingerprint = str(f.get("fingerprint", "")).strip()

    allow_tags      = suppressions.get("allow_tags") or []
    deny_rule_ids   = suppressions.get("deny_rule_ids") or []
    # v0.3.0 — supressão por fingerprint
    deny_fingerprints = [str(fp).strip() for fp in (suppressions.get("deny_fingerprints") or [])]

    if rule_id and rule_id in deny_rule_ids:
        return True
    if any(t in allow_tags for t in tags):
        return True
    # Suprime apenas se o fingerprint for não-vazio e estiver na lista
    if fingerprint and fingerprint in deny_fingerprints:
        return True

    return False


# ---------------------------------------------------------------------------
# Hard-fails
# ---------------------------------------------------------------------------

def _matches_when(f: Dict[str, Any], when: Dict[str, Any]) -> bool:
    if "domain" in when and f.get("domain") != when["domain"]:
        return False

    sev  = f.get("severity")
    conf = f.get("confidence")

    if "severity_in" in when and sev not in when["severity_in"]:
        return False
    if "confidence_in" in when and conf not in when["confidence_in"]:
        return False
    if "is_new" in when and f.get("is_new") != when["is_new"]:
        return False

    if "metadata" in when:
        meta_when = when["metadata"] or {}
        meta      = f.get("metadata") or {}

        for k, v in meta_when.items():
            if k == "tags_any":
                tags = meta.get("tags") or []
                if not any(t in tags for t in v):
                    return False
            else:
                if meta.get(k) != v:
                    return False

    return True


def _evaluate_hard_fails(
    findings_new: List[Dict[str, Any]],
    policy: Dict[str, Any],
) -> List[HardFailHit]:
    hits: List[HardFailHit] = []
    for rule in policy.get("hard_fails", []):
        rule_id = rule.get("id", "hard_fail")
        reason  = rule.get("reason", rule_id)
        when    = rule.get("when") or {}

        for f in findings_new:
            if _matches_when(f, when):
                hits.append(HardFailHit(
                    rule_id=rule_id,
                    reason=reason,
                    finding_fingerprint=str(f.get("fingerprint", "")),
                ))

    # Dedup por (rule_id, fingerprint)
    uniq = {}
    for h in hits:
        uniq[(h.rule_id, h.finding_fingerprint)] = h
    return list(uniq.values())


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

def _score_finding(f: Dict[str, Any], policy: Dict[str, Any]) -> float:
    scoring     = policy["scoring"]
    penalties   = scoring["penalties"]
    multipliers = scoring.get("multipliers", {})

    sev  = f.get("severity", "info")
    base = float(penalties.get(sev, 0))

    conf_map  = multipliers.get("confidence") or {}
    conf      = f.get("confidence", "unknown")
    conf_mult = float(conf_map.get(conf, 1.0))

    fix_map   = multipliers.get("fix_available") or {}
    fix_avail = bool(f.get("fix_available", False))
    fix_mult  = float(fix_map.get(True if fix_avail else False, 1.0))

    return base * conf_mult * fix_mult


def _decide(
    score: int,
    hard_fails: List[HardFailHit],
    policy: Dict[str, Any],
) -> Decision:
    if hard_fails:
        return "FAIL"

    d = policy["decision"]

    if score >= int(d["pass_min_score"]):
        return "PASS"
    if score >= int(d["review_min_score"]):
        return "REVIEW"
    return "FAIL"


# ---------------------------------------------------------------------------
# Reasons / seleção de findings para o comentário
# ---------------------------------------------------------------------------

def _build_reasons(
    findings_new: List[Dict[str, Any]],
    hard_fails:   List[HardFailHit],
    policy:       Dict[str, Any],
) -> List[str]:
    max_reasons = int((policy.get("reporting") or {}).get("max_reasons", 3))

    if hard_fails:
        seen: set = set()
        reasons: List[str] = []
        for h in hard_fails:
            if h.reason not in seen:
                reasons.append(h.reason)
                seen.add(h.reason)
            if len(reasons) >= max_reasons:
                break
        return reasons

    sorted_findings = sorted(findings_new, key=_sort_key)
    reasons = []
    for f in sorted_findings:
        reasons.append(f.get("title", "Issue"))
        if len(reasons) >= max_reasons:
            break
    return reasons


def _select_findings_to_show(
    findings_new: List[Dict[str, Any]],
    hard_fails:   List[HardFailHit],
    policy:       Dict[str, Any],
) -> List[Dict[str, Any]]:
    max_items = int((policy.get("reporting") or {}).get("max_findings_in_comment", 10))

    hard_fail_fps = {h.finding_fingerprint for h in hard_fails if h.finding_fingerprint}

    shown:   List[Dict[str, Any]] = []
    seen_fp: set = set()

    # 1) hard-fail findings primeiro
    for f in sorted(findings_new, key=_sort_key):
        fp = str(f.get("fingerprint", ""))
        if fp and fp in hard_fail_fps and fp not in seen_fp:
            shown.append(f)
            seen_fp.add(fp)
            if len(shown) >= max_items:
                return shown

    # 2) resto por severidade
    for f in sorted(findings_new, key=_sort_key):
        fp = str(f.get("fingerprint", ""))
        if fp and fp in seen_fp:
            continue
        shown.append(f)
        if fp:
            seen_fp.add(fp)
        if len(shown) >= max_items:
            break

    return shown


def _sort_key(f: Dict[str, Any]) -> Tuple[int, str]:
    sev = f.get("severity", "info")
    return (SEVERITY_ORDER.get(sev, 99), f.get("title", ""))


# ---------------------------------------------------------------------------
# Ignore paths
# ---------------------------------------------------------------------------

def should_ignore_path(path: str, patterns: List[str]) -> bool:
    if not path:
        return False

    path = path.replace("\\", "/")

    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
        if pattern.endswith("/") and pattern in path:
            return True

    return False