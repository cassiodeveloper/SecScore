# SecScore

**Security score that matters.**

SecScore takes the output of existing security tools  
(SAST, SCA, IaC, Container) and turns them into a **clear, decision-ready security score for Pull Requests**.

No dashboards.  
No vendor lock-in.  
No guesswork.

---

## What SecScore does

SecScore focuses on **measurement**, not control.

For every Pull Request, it:
1. Collects results from security scanners already configured in your CI
2. Evaluates **only the new risk introduced by the PR**
3. Applies explicit, versioned security policies
4. Produces a security score (0–100)
5. Publishes:
   - a clear comment on the PR
   - a status check (PASS / REVIEW / FAIL)

SecScore provides the signal.  
Your process decides what to do with it.

---

## What SecScore does NOT do

- Does not run scanners
- Does not replace SAST, SCA, IaC or container tools
- Does not provide dashboards
- Does not hide logic behind black boxes
- Does not make decisions for you

SecScore measures risk so decisions can be made explicitly.

---

## Why Pull Requests

Pull Requests are where risk is introduced.

SecScore evaluates:
- **delta only** — what changed in this PR
- **new findings only** — no legacy punishment
- **explainable signals** — not raw scanner noise

This keeps security feedback actionable and fair.

---

## Inputs

- `findings.json` — normalized security findings  
- `policy-pr.yml` — policy-as-code defining scoring and thresholds

---

## Outputs

- Security score (0–100)
- Pull Request comment with top findings and reasons
- Status check:
  - `PASS` → no significant new risk
  - `REVIEW` → security review recommended
  - `FAIL` → unacceptable new risk detected

Exit codes:
- `0` → PASS
- `1` → REVIEW
- `2` → FAIL

---

## Example Pull Request comment