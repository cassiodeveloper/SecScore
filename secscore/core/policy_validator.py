"""
secscore/core/policy_validator.py

Valida a estrutura do policy YAML antes de o engine consumi-la.
"""
from __future__ import annotations

from typing import Any, Dict, List


class PolicyValidationError(Exception):
    def __init__(self, errors: List[str]):
        self.errors = errors
        bullet = "\n  - ".join(errors)
        super().__init__(f"Policy inválida ({len(errors)} erro(s)):\n  - {bullet}")


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CONFIDENCES = {"high", "medium", "low", "unknown"}
_VALID_DOMAINS     = {"sast", "sca", "iac", "container"}


def validate_policy(policy: Dict[str, Any]) -> None:
    errors: List[str] = []

    # --- decision ---
    decision = policy.get("decision")
    if not isinstance(decision, dict):
        errors.append("'decision' é obrigatório e deve ser um mapeamento.")
    else:
        for key in ("pass_min_score", "review_min_score"):
            val = decision.get(key)
            if val is None:
                errors.append(f"'decision.{key}' é obrigatório.")
            elif not isinstance(val, (int, float)) or not (0 <= val <= 100):
                errors.append(f"'decision.{key}' deve ser um número entre 0 e 100, recebido: {val!r}.")

        pass_min   = decision.get("pass_min_score",   100)
        review_min = decision.get("review_min_score",   0)
        if isinstance(pass_min, (int, float)) and isinstance(review_min, (int, float)):
            if pass_min < review_min:
                errors.append(
                    f"'decision.pass_min_score' ({pass_min}) não pode ser menor que "
                    f"'decision.review_min_score' ({review_min})."
                )

    # --- scoring ---
    scoring = policy.get("scoring")
    if not isinstance(scoring, dict):
        errors.append("'scoring' é obrigatório e deve ser um mapeamento.")
    else:
        base = scoring.get("base_score")
        if base is None:
            errors.append("'scoring.base_score' é obrigatório.")
        elif not isinstance(base, (int, float)) or base <= 0:
            errors.append(f"'scoring.base_score' deve ser um número positivo, recebido: {base!r}.")

        penalties = scoring.get("penalties")
        if not isinstance(penalties, dict):
            errors.append("'scoring.penalties' é obrigatório e deve ser um mapeamento.")
        else:
            for sev, val in penalties.items():
                if sev not in _VALID_SEVERITIES:
                    errors.append(
                        f"'scoring.penalties' contém severidade desconhecida: {sev!r}. "
                        f"Válidos: {sorted(_VALID_SEVERITIES)}."
                    )
                if not isinstance(val, (int, float)) or val < 0:
                    errors.append(
                        f"'scoring.penalties.{sev}' deve ser um número >= 0, recebido: {val!r}."
                    )

        multipliers = scoring.get("multipliers", {})
        if not isinstance(multipliers, dict):
            errors.append("'scoring.multipliers' deve ser um mapeamento.")
        else:
            conf_map = multipliers.get("confidence", {})
            if not isinstance(conf_map, dict):
                errors.append("'scoring.multipliers.confidence' deve ser um mapeamento.")
            else:
                for conf_key in conf_map:
                    if conf_key not in _VALID_CONFIDENCES:
                        errors.append(
                            f"'scoring.multipliers.confidence' contém chave desconhecida: {conf_key!r}. "
                            f"Válidos: {sorted(_VALID_CONFIDENCES)}."
                        )

    # --- hard_fails ---
    hard_fails = policy.get("hard_fails", [])
    if not isinstance(hard_fails, list):
        errors.append("'hard_fails' deve ser uma lista.")
    else:
        for i, rule in enumerate(hard_fails):
            prefix = f"hard_fails[{i}]"
            if not isinstance(rule, dict):
                errors.append(f"{prefix} deve ser um mapeamento.")
                continue
            if not rule.get("id"):
                errors.append(f"{prefix}.id é obrigatório.")
            when = rule.get("when", {})
            if not isinstance(when, dict):
                errors.append(f"{prefix}.when deve ser um mapeamento.")
            else:
                domain = when.get("domain")
                if domain and domain not in _VALID_DOMAINS:
                    errors.append(
                        f"{prefix}.when.domain valor desconhecido: {domain!r}. "
                        f"Válidos: {sorted(_VALID_DOMAINS)}."
                    )
                sev_in = when.get("severity_in", [])
                if not isinstance(sev_in, list):
                    errors.append(f"{prefix}.when.severity_in deve ser uma lista.")
                else:
                    for s in sev_in:
                        if s not in _VALID_SEVERITIES:
                            errors.append(
                                f"{prefix}.when.severity_in contém valor desconhecido: {s!r}. "
                                f"Válidos: {sorted(_VALID_SEVERITIES)}."
                            )

    # --- ignore_paths ---
    ignore_paths = policy.get("ignore_paths", [])
    if not isinstance(ignore_paths, list):
        errors.append("'ignore_paths' deve ser uma lista de strings.")
    else:
        for i, p in enumerate(ignore_paths):
            if not isinstance(p, str):
                errors.append(f"'ignore_paths[{i}]' deve ser uma string, recebido: {p!r}.")

    # --- suppressions (v0.3.0: inclui deny_fingerprints) ---
    suppressions = policy.get("suppressions", {})
    if not isinstance(suppressions, dict):
        errors.append("'suppressions' deve ser um mapeamento.")
    else:
        deny_fps = suppressions.get("deny_fingerprints", [])
        if not isinstance(deny_fps, list):
            errors.append("'suppressions.deny_fingerprints' deve ser uma lista de strings.")
        else:
            for i, fp in enumerate(deny_fps):
                if not isinstance(fp, str) or not fp.strip():
                    errors.append(
                        f"'suppressions.deny_fingerprints[{i}]' deve ser uma string não-vazia, "
                        f"recebido: {fp!r}."
                    )

    # --- reporting ---
    reporting = policy.get("reporting", {})
    if not isinstance(reporting, dict):
        errors.append("'reporting' deve ser um mapeamento.")
    else:
        for field in ("max_findings_in_comment", "max_reasons"):
            val = reporting.get(field)
            if val is not None and (not isinstance(val, int) or val <= 0):
                errors.append(f"'reporting.{field}' deve ser um inteiro positivo, recebido: {val!r}.")

    if errors:
        raise PolicyValidationError(errors)