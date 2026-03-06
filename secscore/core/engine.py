from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import json
import fnmatch

# Decisões do SecScore (PR mode)
Decision = str  # "PASS" | "REVIEW" | "FAIL"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

@dataclass(frozen=True)
class EngineInput:
    findings: Dict[str, Any]      # conteúdo do findings.json (já normalizado)
    policy: Dict[str, Any]        # conteúdo do policy-pr.yml (já parseado)
    mode: str = "pull_request"    # por enquanto só PR

@dataclass(frozen=True)
class HardFailHit:
    rule_id: str
    reason: str
    finding_fingerprint: str

@dataclass(frozen=True)
class EngineResult:
    score: int
    decision: Decision
    reasons: List[str]                    # top reasons (max 3)
    hard_fails: List[HardFailHit]
    findings_new: List[Dict[str, Any]]    # findings novos (já filtrados e sem supressões)
    findings_shown: List[Dict[str, Any]]  # subset priorizado pra report (máx N)
    penalties_total: float

def run_engine(inp: EngineInput) -> EngineResult:
    """
    Lógica principal:
    - Filtra apenas findings novos no PR
    - Aplica supressões
    - Avalia hard-fails
    - Calcula score
    - Decide PASS/REVIEW/FAIL
    - Seleciona findings para exibir no comentário
    """
    policy = inp.policy
    if isinstance(inp.findings, list):
        findings_all = inp.findings
    else:
        findings_all = inp.findings.get("findings", [])

    ignore_patterns = inp.policy.get("ignore_paths", [])

    filtered_findings = []
      
    for f in findings_all:

        asset = f.get("asset", {})
        path = asset.get("path")
        path = path.replace("\\", "/")

        if should_ignore_path(path, ignore_patterns):
            continue

        filtered_findings.append(f)

    findings_all = filtered_findings

    # 1) Filtrar somente is_new=true (PR mode)
    findings_new = [f for f in findings_all if bool(f.get("is_new", False))]

    # 2) Aplicar supressões (tags/rule_ids etc.)
    suppressions = policy.get("suppressions") or {}
    findings_new = [f for f in findings_new if not _is_suppressed(f, suppressions)]

    # 3) Hard-fails
    hard_fails = _evaluate_hard_fails(findings_new, policy)

    # 4) Score
    base_score = int(policy["scoring"]["base_score"])
    penalties_total = sum(_score_finding(f, policy) for f in findings_new)
    score = max(0, int(round(base_score - penalties_total)))

    # 5) Decisão
    decision = _decide(score, hard_fails, policy)

    # 6) Reasons (top 3)
    reasons = _build_reasons(findings_new, hard_fails, policy)

    # 7) Seleção do que mostrar no comentário
    findings_shown = _select_findings_to_show(findings_new, hard_fails, policy)

    return EngineResult(score=score, decision=decision, reasons=reasons, hard_fails=hard_fails, findings_new=findings_new, findings_shown=findings_shown, penalties_total=float(penalties_total))

# -------------------------
# Helpers (core rules)
# -------------------------
def _is_suppressed(f: Dict[str, Any], suppressions: Dict[str, Any]) -> bool:
    meta = f.get("metadata") or {}
    tags = meta.get("tags") or []
    rule_id = meta.get("rule_id")

    allow_tags = suppressions.get("allow_tags") or []
    deny_rule_ids = suppressions.get("deny_rule_ids") or []

    if rule_id and rule_id in deny_rule_ids:
        return True
    if any(t in allow_tags for t in tags):
        return True
    return False

def _matches_when(f: Dict[str, Any], when: Dict[str, Any]) -> bool:
    if "domain" in when and f.get("domain") != when["domain"]:
        return False

    sev = f.get("severity")
    conf = f.get("confidence")

    if "severity_in" in when and sev not in when["severity_in"]:
        return False
    if "confidence_in" in when and conf not in when["confidence_in"]:
        return False
    if "is_new" in when and f.get("is_new") != when["is_new"]:
        return False

    if "metadata" in when:
        meta_when = when["metadata"] or {}
        meta = f.get("metadata") or {}

        for k, v in meta_when.items():
            if k == "tags_any":
                tags = meta.get("tags") or []
                if not any(t in tags for t in v):
                    return False
            else:
                if meta.get(k) != v:
                    return False

    return True

def _evaluate_hard_fails(findings_new: List[Dict[str, Any]], policy: Dict[str, Any]) -> List[HardFailHit]:
    hits: List[HardFailHit] = []
    for rule in policy.get("hard_fails", []):
        rule_id = rule.get("id", "hard_fail")
        reason = rule.get("reason", rule_id)
        when = rule.get("when") or {}

        for f in findings_new:
            if _matches_when(f, when):
                hits.append(
                    HardFailHit(
                        rule_id=rule_id,
                        reason=reason,
                        finding_fingerprint=str(f.get("fingerprint", "")),
                    )
                )
    # Dedup por (rule_id, fingerprint)
    uniq = {}
    for h in hits:
        uniq[(h.rule_id, h.finding_fingerprint)] = h
    return list(uniq.values())

def _score_finding(f: Dict[str, Any], policy: Dict[str, Any]) -> float:
    scoring = policy["scoring"]
    penalties = scoring["penalties"]
    multipliers = scoring.get("multipliers", {})

    sev = f.get("severity", "info")
    base = float(penalties.get(sev, 0))

    conf_map = (multipliers.get("confidence") or {})
    conf = f.get("confidence", "unknown")
    conf_mult = float(conf_map.get(conf, 1.0))

    fix_map = (multipliers.get("fix_available") or {})
    fix_avail = bool(f.get("fix_available", False))
    fix_mult = float(fix_map.get(True if fix_avail else False, 1.0))

    return base * conf_mult * fix_mult

def _decide(score: int, hard_fails: List[HardFailHit], policy: Dict[str, Any]) -> Decision:
    if hard_fails:
        return "FAIL"
    
    d = policy["decision"]
    
    if score >= int(d["pass_min_score"]):
        return "PASS"
    if score >= int(d["review_min_score"]):
        return "REVIEW"
    return "FAIL"

def _build_reasons(findings_new: List[Dict[str, Any]], hard_fails: List[HardFailHit], policy: Dict[str, Any]) -> List[str]:
    max_reasons = int((policy.get("reporting") or {}).get("max_reasons", 3))

    if hard_fails:
        # reasons = motivos de hard-fail (dedup)
        seen = set()
        reasons: List[str] = []
        for h in hard_fails:
            if h.reason not in seen:
                reasons.append(h.reason)
                seen.add(h.reason)
            if len(reasons) >= max_reasons:
                break
        return reasons

    # Sem hard fail: usar os títulos das findings mais severas
    sorted_findings = sorted(findings_new, key=_sort_key)
    reasons = []
    for f in sorted_findings:
        t = f.get("title", "Issue")
        reasons.append(t)
        if len(reasons) >= max_reasons:
            break
    
    return reasons

def _select_findings_to_show(findings_new: List[Dict[str, Any]], hard_fails: List[HardFailHit], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    max_items = int((policy.get("reporting") or {}).get("max_findings_in_comment", 10))

    # Prioriza: findings que bateram hard-fail primeiro, depois por severidade
    hard_fail_fps = {h.finding_fingerprint for h in hard_fails if h.finding_fingerprint}

    shown: List[Dict[str, Any]] = []
    seen_fp = set()

    # 1) hard-fail findings
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

def should_ignore_path(path: str, patterns: list[str]) -> bool:
    if not path:
        return False

    path = path.replace("\\", "/")

    for pattern in patterns:

        # wildcard
        if fnmatch.fnmatch(path, pattern):
            return True

        # directory match
        if pattern.endswith("/") and pattern in path:
            return True

    return False