import json
from pathlib import Path

def normalize_sarif(path: str):

    data = json.loads(Path(path).read_text(encoding="utf-8"))

    findings = []

    for run in data.get("runs", []):

        for result in run.get("results", []):

            location = None

            if result.get("locations"):
                location = result["locations"][0].get("physicalLocation", {})

            asset_path = None
            asset_line = None

            if location:
                artifact = location.get("artifactLocation", {})
                region = location.get("region", {})

                asset_path = artifact.get("uri")
                asset_line = region.get("startLine")

            severity = map_severity(result.get("level") or result.get("properties", {}).get("severity"))

            findings.append({
                "id": result.get("ruleId"),
                "title": result.get("message", {}).get("text"),
                "severity": severity,
                "domain": "sast",
                "asset": {
                    "path": asset_path,
                    "line": asset_line
                },
                "metadata": {},
                "is_new": True
            })
    
    return { "findings": findings }

def map_severity(level):

    level = (level or "").lower()

    if level == "error":
        return "high"

    if level == "warning":
        return "medium"

    if level == "note":
        return "low"

    return "low"