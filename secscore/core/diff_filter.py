import subprocess
import re
from typing import List, Dict, Any, Tuple

HUNK_REGEX = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# Regex de validação para base_ref: permite refs git válidos
# (branches, tags, SHAs) sem caracteres perigosos para o shell.
_SAFE_REF_RE = re.compile(r'^[\w][\w/.\-]*$')

WINDOW = 10


def _validate_ref(ref: str) -> str:
    """
    Valida que o ref git é seguro antes de passá-lo ao subprocess.
    Levanta ValueError se o valor contiver caracteres inesperados.
    """
    ref = ref.strip()
    if not ref:
        raise ValueError("base_ref não pode ser vazio.")
    if not _SAFE_REF_RE.match(ref):
        raise ValueError(
            f"base_ref contém caracteres inválidos: {ref!r}. "
            "Apenas letras, números, '/', '.', '-' e '_' são permitidos."
        )
    return ref


def get_changed_ranges(base_ref: str = "origin/main") -> Dict[str, List[Tuple[int, int]]]:
    # FIX: validar base_ref antes de passá-lo ao subprocess para evitar
    # injeção de comandos via variável de ambiente no CI.
    base_ref = _validate_ref(base_ref)

    diff = subprocess.check_output(
        ["git", "diff", "--unified=0", base_ref, "HEAD"],
        text=True
    )

    changed: Dict[str, List[Tuple[int, int]]] = {}
    current_file = None

    for line in diff.splitlines():

        if line.startswith("+++ b/"):
            current_file = line[6:].strip().replace("\\", "/").lstrip("./")
            if current_file not in changed:
                changed[current_file] = []
            continue

        match = HUNK_REGEX.match(line)

        if match and current_file:
            start = int(match.group(1))
            length = int(match.group(2) or 1)

            start = max(1, start - WINDOW)
            end = start + length + WINDOW

            changed[current_file].append((start, end))

    return changed


def path_matches(path: str, repo_path: str) -> bool:

    path = path.replace("\\", "/").lstrip("./")

    return path.endswith(repo_path) or repo_path.endswith(path)


def line_in_ranges(line: int, ranges: List[Tuple[int, int]]) -> bool:

    for start, end in ranges:
        if start <= line <= end:
            return True

    return False


def filter_findings_by_diff(findings: List[Dict[str, Any]], changed_ranges: Dict[str, List[Tuple[int, int]]]) -> List[Dict[str, Any]]:

    filtered = []

    for finding in findings:

        asset = finding.get("asset", {})
        path = asset.get("path")

        if not path:
            continue

        path = path.replace("\\", "/").lstrip("./")

        for changed_file, ranges in changed_ranges.items():

            if not path_matches(path, changed_file):
                continue

            line = asset.get("line") or finding.get("line")

            if line is None:
                filtered.append(finding)
                break

            try:
                line = int(line)
            except:
                filtered.append(finding)
                break

            if line_in_ranges(line, ranges):
                filtered.append(finding)
                break

    return filtered