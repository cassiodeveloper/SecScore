"""
secscore/normalizers/sarif.py

Normaliza um ou mais arquivos SARIF para o formato interno de findings.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Union


def normalize_sarif(path: Union[str, List[str]]) -> dict:
    """
    Aceita um único path (str) ou uma lista de paths (List[str]).
    Faz o merge de todos os runs/results em um único envelope de findings,
    deduplicando por (ruleId, asset_path, asset_line) para evitar
    duplicatas quando o mesmo achado aparece em dois SARIFs diferentes.
    """
    paths = [path] if isinstance(path, str) else path

    all_findings = []
    seen_keys = set()

    for p in paths:
        findings = _parse_single(p)
        for f in findings:
            # Chave de dedup: ruleId + path + line
            dedup_key = (
                f.get("id"),
                (f.get("asset") or {}).get("path"),
                (f.get("asset") or {}).get("line"),
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            all_findings.append(f)

    return {"findings": all_findings}


def _parse_single(path: str) -> list:
    """Parseia um único arquivo SARIF e retorna lista de findings."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []

    for run in data.get("runs", []):
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "unknown")
        )

        for result in run.get("results", []):
            location = None
            if result.get("locations"):
                location = result["locations"][0].get("physicalLocation", {})

            asset_path = None
            asset_line = None

            if location:
                artifact = location.get("artifactLocation", {})
                region   = location.get("region", {})
                asset_path = artifact.get("uri")
                asset_line = region.get("startLine")

            props_severity = result.get("properties", {}).get("severity", "")
            level          = result.get("level", "")
            severity       = map_severity(level=level, props_severity=props_severity)

            findings.append({
                "id":     result.get("ruleId"),
                "title":  result.get("message", {}).get("text"),
                "severity": severity,
                "domain": "sast",
                "asset": {
                    "path": asset_path,
                    "line": asset_line,
                },
                "metadata": {
                    "tool": tool_name,
                },
                "is_new": True,
            })

    return findings


def map_severity(level: str, props_severity: str = "") -> str:
    """
    Mapeia para os níveis internos do SecScore: critical, high, medium, low, info.

    Prioridade:
      1. properties.severity  (valores explícitos emitidos pelo scanner)
      2. level do SARIF       (error / warning / note)
    """
    normalized = (props_severity or "").lower().strip()
    if normalized in ("critical", "high", "medium", "low", "info"):
        return normalized

    normalized_level = (level or "").lower().strip()

    if normalized_level == "error":
        return "high"
    if normalized_level == "warning":
        return "medium"
    if normalized_level == "note":
        return "low"

    return "low"