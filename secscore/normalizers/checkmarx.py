import json


def normalize(data):

    findings = []

    for r in data.get("results", []):

        node = None

        nodes = r.get("nodes") or []
        node = nodes[0] if nodes else None

        finding = {
            "id": r.get("resultHash"),
            "title": r.get("queryName"),
            "severity": r.get("severity", "").lower(),
            "domain": "sast",
            "asset": {
                "path": node.get("fileName") if node else None,
                "line": node.get("line") if node else None
            },
            "metadata": {
                "cwe": r.get("cweID"),
                "cvss": r.get("cvssScore"),
                "language": r.get("languageName")
            }
        }

        findings.append(finding)

    return findings


# opcional: modo CLI para debug
def normalize_file(input_file, output_file):

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = normalize(data)

    out = {
        "findings": findings
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 3:
        print("Usage: checkmarx.py input.json output.json")
        sys.exit(1)

    normalize_file(sys.argv[1], sys.argv[2])