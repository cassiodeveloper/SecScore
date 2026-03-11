![CI](https://github.com/cassiodeveloper/secscore/actions/workflows/ci.yml/badge.svg)
![GitHub release](https://img.shields.io/github/v/release/cassiodeveloper/secscore)
![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![GitHub Action](https://img.shields.io/badge/github-action-ready)

# SecScore

🇺🇸 English | 🇧🇷 [Português](README.pt-br.md)

**Security Score that matters.**

```
Security Scanner
       ↓
      SARIF
       ↓
    SecScore
       ↓
 PASS / REVIEW / FAIL
```

SecScore is a lightweight security scoring engine for CI/CD pipelines.
It evaluates findings from security scanners and calculates a **single security score for a Pull Request**, allowing teams to automatically decide whether a change should **PASS, require REVIEW, or FAIL**.

The tool is scanner-agnostic and works with **SARIF**, making it compatible with most modern security scanners.

---

## Why SecScore

Security scanners generate findings.
But pipelines need **decisions**.

```
Scanner → Findings → SecScore → Score → Decision

Score: 82 / 100
Decision: REVIEW
```

---

## Key Features

- Security score for Pull Requests
- Hard fail rules for critical vulnerabilities
- SARIF compatible (Snyk, CodeQL, Semgrep, Checkmarx, etc.)
- Multi-SARIF support — pass multiple scanner outputs in one run
- Diff-aware filtering — evaluates only findings introduced in the PR
- Suppressions by fingerprint — suppress confirmed false positives traceably
- GitHub Action ready
- Policy-driven security decisions
- Lightweight and fast
- Open source

---

## How It Works

```
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
```

Supported scanners:

- [x] Snyk
- [x] Semgrep
- [x] CodeQL
- [x] Checkmarx
- [x] Trivy
- [x] Any SARIF-compatible scanner

## Supported Inputs

| Scanner       | Format       |
|---------------|--------------|
| Snyk          | SARIF        |
| CodeQL        | SARIF        |
| Semgrep       | SARIF        |
| Checkmarx     | SARIF        |
| Checkmarx API | JSON         |

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

Single SARIF file:

```
python -m secscore.cli.main pr \
  --sarif examples/example-snyk.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Multiple SARIF files (v0.3.0+):

```
python -m secscore.cli.main pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

> **Note:** use `--no-diff-aware` when running locally without a full git history.
> In CI, diff-aware is enabled by default and requires `fetch-depth: 0` in the checkout step.

Example output:

```
Score: 85 / 100
Decision: PASS
```

---

## GitHub Action

Minimal example:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: results.sarif
```

Multiple scanners (v0.3.0+):

```yaml
- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: "semgrep.sarif,trivy.sarif"
```

Disable diff-aware:

```yaml
- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: results.sarif
    no_diff_aware: "true"
```

---

## Policy-Driven Security

```yaml
base_score: 100

penalties:
  critical: 40
  high: 20
  medium: 7
  low: 2

hard_fails:
  - id: SAST_CRITICAL_HIGH_CONF
    when:
      domain: sast
      severity_in: ["critical", "high"]
      is_new: true
    reason: "New critical/high SAST finding"
```

### Suppressing false positives by fingerprint (v0.3.0+)

```yaml
suppressions:
  deny_fingerprints:
    - "abc123def456"   # confirmed false positive — XSS in test helper
```

Obtain the fingerprint from `secscore-result.json > hard_fails[].finding_fingerprint`.

---

## Examples

Example SARIF files:

```
examples/
  example-snyk.sarif
  example-checkmarx.sarif
```

Example workflows:

```
examples/workflows/
  example-minimal.yml
  example-snyk.yml
  example-checkmarx.yml
  example-checkmarx-api.yml
  example-multi-scanner.yml
```

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

[SECURITY.md](SECURITY.md)

---

## Contributing

Contributions are welcome. Please read:

[CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

Free for non-commercial use. Commercial use — including incorporation into a paid product,
service, or platform — requires explicit permission from the author.

[LICENSE](LICENSE) · [polyformproject.org/licenses/noncommercial/1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/)

---

## Philosophy

Security scanners generate noise.

SecScore focuses on what actually matters:

**clear, automated security decisions in CI/CD pipelines.**