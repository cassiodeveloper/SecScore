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
- Optional M.A.R.I.A integration — submits SecScore decision payload (`Score`, `Decision`, `Summary`) after analysis
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
pip install -e .
```

---

## 5-Minute Quickstart

1. Run with SARIF and policy:

```bash
secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

2. Check outputs:
- `pr-comment.md` (PR-ready markdown summary)
- `secscore-result.json` (structured result)
- Optional: `secscore-report.html` (visual report generated when `--html-output true`)

3. Optional: submit result to M.A.R.I.A:

```bash
SECSCORE_ALLOW_PRIVATE_MARIA_URLS=true secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --maria-url http://localhost:5213/api/secscore/submissions \
  --maria-repository-id 11111111-2222-3333-4444-555555555555 \
  --token YOUR_MARIA_TOKEN \
  --no-diff-aware
```

---

## Copy/Paste Scenarios

Use these commands to validate expected outcomes quickly:

### PASS

```bash
secscore pr \
  --sarif tests/fixtures/pass.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Expected: `Decision: PASS`

### REVIEW

```bash
secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Expected: `Decision: REVIEW`

### FAIL

```bash
secscore pr \
  --sarif tests/fixtures/fail.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Expected: `Decision: FAIL`

---

## Choose Input Mode

| Mode | When to use | Required flags |
|------|-------------|----------------|
| SARIF (`--sarif`) | You already generated scanner SARIF files in CI | `--sarif`, `--policy` |
| Findings JSON (`--findings`) | You already have normalized findings JSON | `--findings`, `--policy` |
| Provider (`--provider checkmarx`) | You want SecScore to fetch findings directly from provider API | `--provider checkmarx`, provider flags, `--policy` |

---

## Running Locally

Single SARIF file:

```
secscore pr \
  --sarif examples/example-snyk.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Multiple SARIF files (v0.3.0+):

```
secscore pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Send consolidated findings to M.A.R.I.A (token provided at invocation):

```bash
secscore pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --maria-url https://demo.mariaappsec.com/api/secscore/submissions \
  --maria-repository-id 11111111-2222-3333-4444-555555555555 \
  --token YOUR_MARIA_TOKEN \
  --no-diff-aware
```

For `/api/secscore/submissions`, SecScore auto-fills required submission fields
(`Score`, `Decision`, `Summary`, `CommitSha`, `BranchName`, `PipelineName`, `PipelineRunId`, `SubmissionKey`).
You can override them with:
`--maria-submission-key`, `--maria-commit-sha`, `--maria-branch-name`, `--maria-pipeline-name`, `--maria-pipeline-run-id`, `--maria-pull-request-id`.

### M.A.R.I.A policy import behavior

- When M.A.R.I.A integration is configured (`--maria-url`, `--maria-repository-id`, `--token`/`--maria-token`),
  SecScore imports policy from M.A.R.I.A by default.
- The imported policy is saved on every run to `policy/policy-maria.yml`.
- The execution then uses `policy/policy-maria.yml` as the effective policy.
- Use `--maria-import-policy false` to keep using the local policy file from `--policy`.

For local PR testing without opening a real PR:

```bash
SECSCORE_ALLOW_PRIVATE_MARIA_URLS=true SECSCORE_PULL_REQUEST_ID=local-pr-001 secscore pr \
  --sarif semgrep.sarif \
  --policy policy/policy-pr.yml \
  --maria-url http://localhost:5213/api/secscore/submissions \
  --maria-repository-id 11111111-2222-3333-4444-555555555555 \
  --token YOUR_MARIA_TOKEN \
  --no-diff-aware
```

In GitHub Actions, SecScore auto-detects the pull request number from the
`pull_request` event. Other CI variables supported: `CI_MERGE_REQUEST_IID`,
`CI_MERGE_REQUEST_ID`, `SYSTEM_PULLREQUEST_PULLREQUESTID`, and `BITBUCKET_PR_ID`.

> **Note:** use `--no-diff-aware` when running locally without a full git history.
> In CI, diff-aware is enabled by default and requires `fetch-depth: 0` in the checkout step.

Example output:

```
Score: 85 / 100
Decision: PASS
```

Generate a visual HTML report from the standard JSON output:

```bash
secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware \
  --html-output true
```

The JSON result is always generated. When HTML output is enabled, SecScore also writes
`secscore-report.html` by default. Use `--html-out custom-report.html` to choose another path.

---

## GitHub Action

Recommended workflow permissions:

```yaml
permissions:
  contents: read
  checks: write
  pull-requests: write
  issues: write
```

SecScore needs `contents: read` to access the repository, `checks: write` to create the status check,
and `issues: write`/`pull-requests: write` to upsert PR comments and manage the review label.

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
    maria-url: "https://demo.mariaappsec.com/api/secscore/submissions"
    maria-repository-id: "11111111-2222-3333-4444-555555555555"
    maria-token: ${{ secrets.MARIA_TOKEN }}
```

Generate and publish the HTML report as a workflow artifact:

```yaml
- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: results.sarif
    html_output: "true"

- name: Upload SecScore report
  uses: actions/upload-artifact@v4
  with:
    name: secscore-report
    path: |
      secscore-result.json
      secscore-report.html
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

### Minimal policy

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

### Recommended policy (example)

```yaml
scoring:
  base_score: 100
  penalties:
    critical: 40
    high: 20
    medium: 7
    low: 2
  multipliers:
    confidence:
      high: 1.0
      medium: 0.8
      low: 0.5

decision:
  pass_min_score: 85
  review_min_score: 51

hard_fails:
  - id: CRITICAL_NEW
    when:
      severity_in: ["critical"]
      is_new: true
    reason: "New critical finding"

ignore_paths:
  - "node_modules/**"
  - "dist/**"
```

### Suppressing false positives by fingerprint (v0.3.0+)

```yaml
suppressions:
  deny_fingerprints:
    - "abc123def456"   # confirmed false positive — XSS in test helper
```

Obtain the fingerprint from `secscore-result.json > hard_fails[].finding_fingerprint`.

---

## Troubleshooting

- `404 Not Found` on M.A.R.I.A: endpoint path is wrong; use `/api/secscore/submissions`.
- `400 Bad Request` on M.A.R.I.A: payload contract mismatch (required submission fields missing/invalid).
- `401 Unauthorized` on M.A.R.I.A: invalid token format/value for that environment.
- `403 Forbidden` on M.A.R.I.A: token valid but missing scope/resource access to the target repository.
- `Diff-aware skipped` warning: expected locally without full git history; use `--no-diff-aware`.

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
