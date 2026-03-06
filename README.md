
# SecScore

🇺🇸 English | 🇧🇷 [Português](README.pt-br.md)

**Security Score that matters.**

SecScore is a lightweight security scoring engine for CI/CD pipelines.  
It evaluates findings from security scanners and calculates a **single security score for a Pull Request**, allowing teams to automatically decide whether a change should **PASS, require REVIEW, or FAIL**.

The tool is scanner‑agnostic and works with **SARIF**, making it compatible with most modern security scanners.

---

## Badges

![CI](https://github.com/cassiodeveloper/secscore/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/cassiodeveloper/secscore)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![GitHub Action](https://img.shields.io/badge/github-action-ready-black)

---

## Why SecScore

Security scanners generate findings.  
But pipelines need **decisions**.

Pipeline flow:

Scanner → Findings → SecScore → Score → Decision

Example:

Score: 82 / 100  
Decision: REVIEW

---

## Key Features

- Security score for Pull Requests
- Hard fail rules for critical vulnerabilities
- SARIF compatible (Snyk, CodeQL, Semgrep, Checkmarx, etc.)
- GitHub Action ready
- Policy‑driven security decisions
- Lightweight and fast
- Open source

---

## How It Works

Security Scanner  
↓  
SARIF  
↓  
SecScore Parser  
↓  
Policy Engine  
↓  
Score Calculation  
↓  
PASS / REVIEW / FAIL

---

## Supported Inputs

| Scanner | Format |
|-------|-------|
| Snyk | SARIF |
| CodeQL | SARIF |
| Semgrep | SARIF |
| Checkmarx | SARIF |
| Checkmarx API | JSON |

Most modern security scanners support SARIF.

---

## Installation

Clone the repository:

```
git clone https://github.com/cassiodeveloper/secscore
cd secscore
```

Install dependencies:

```
pip install -r requirements.txt
```

---

## Running Locally

You can test SecScore locally using the provided examples.

```
python -m secscore.cli.main pr   --sarif examples/example-snyk.sarif   --policy policy/policy-pr.yml
```

Example output:

```
Score: 85 / 100
Decision: PASS
```

---

## GitHub Action

Example workflow:

```yaml
name: SecScore PR

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  secscore:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run SecScore
        uses: cassiodeveloper/secscore@v1
        with:
          sarif: results.sarif
```

---

## Policy Driven Security

Example policy:

```yaml
base_score: 100

penalties:
  high: 20
  medium: 10
  low: 5

hard_fail:
  - domain: sast
    severity_in: ["critical"]
    is_new: true
```

---

## Examples

Example SARIF files:

examples/
- example-snyk.sarif
- example-checkmarx.sarif

Example workflows:

examples/workflows/
- example-minimal.yml
- example-snyk.yml
- example-checkmarx.yml
- example-checkmarx-api.yml
- example-multi-scanner.yml

---

## Project Structure

```
secscore/
   adapters/
   cli/
   core/
   normalizers/
   utils/

examples/
policy/
schema/
```

---

## Security

If you discover a vulnerability in this project, please report it responsibly.

See:  
SECURITY.md

---

## Contributing

Contributions are welcome. Please read:

CONTRIBUTING.md

---

## License

This project is licensed under the MIT License.

[LICENSE](LICENSE)

---

## Philosophy

Security scanners generate noise.

SecScore focuses on what actually matters:

**clear, automated security decisions in CI/CD pipelines.**
