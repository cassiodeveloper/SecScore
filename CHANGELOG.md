# Changelog

All notable changes to SecScore will be documented in this file.

The format is based on semantic versioning and follows a simple chronological release history.

---

## v0.3.0 — 2026-03

### Added

* **Multi-SARIF support**: `--sarif` now accepts multiple files as a comma-separated list
  (`--sarif semgrep.sarif,trivy.sarif`) or multiple flags. GitHub Action updated accordingly.
  Findings are deduplicated across files by `(ruleId, path, line)`.
* **Diff-aware filtering enabled by default** in PR mode. SecScore now automatically filters
  findings to only those touching lines changed in the PR. Use `--no-diff-aware` to opt out.
  Gracefully degrades (warning, no abort) when not running inside a git repository or when
  the diff returns no changed files.
* **Suppressions by fingerprint**: policy `suppressions.deny_fingerprints` list allows
  suppressing specific known false positives by their finding fingerprint — traceable and
  reviewable in version control.
* `action.yml` new inputs: `no_diff_aware`, `base_ref`.
* `policy_validator.py` now validates `suppressions.deny_fingerprints` entries.
* Policy version bumped to `1.1` in default policy files.

### Fixed

* `engine.py`: `NoneType` crash when `asset.path` was absent in a finding.
* `sarif.py`: `critical` severity from `properties.severity` (Semgrep, Snyk) was silently
  downgraded to `high`. Now correctly propagated.
* `action.yml`: Python inline block had incorrect indentation causing `SyntaxError` on the
  GitHub Actions runner.
* `diff_filter.py`: `base_ref` argument was passed unsanitized to `subprocess`. Now validated
  against an allowlist regex before use.
* `checkmarx_provider.py`: `get_results` used a hard-coded `limit=1000` with no pagination,
  silently dropping findings beyond the first 1000. Replaced with a paginated loop.
* `policy_validator.py` (new): policy YAML is now validated before reaching the engine.
  Structural errors, unknown severity names, and misconfigured thresholds produce clear
  error messages instead of silently incorrect scores.
* `main.py`: diff-aware with empty `changed_ranges` was silently discarding all findings,
  causing every run to score 100 and return PASS. Now skips filtering when diff is empty
  and warns the user.

---

## v0.2.0 — 2026-03

### Added

* Diff-aware filtering to evaluate only findings introduced in the Pull Request.
* **Security Diff** section in PR comments showing vulnerability changes by severity.
* Improved PR comment UX with clearer decision explanation.
* CLI output rendering using Rich for better terminal readability.
* SARIF fixtures for deterministic testing (`PASS`, `REVIEW`, `FAIL` scenarios).
* CI workflow to validate engine behavior during development.

### Improved

* PR comment layout for better readability during code review.
* Decision explanation to clarify why a PR was blocked or requires review.

---

## v0.1.0 — Initial Release

### Added

* Initial SecScore scoring engine.
* SARIF normalization layer for scanner results.
* Policy-based scoring system using YAML configuration.
* PASS / REVIEW / FAIL decision model.
* Pull Request comment generation with security findings summary.
* GitHub CLI entrypoint for CI/CD usage.

---

## Notes

SecScore aims to reduce **security scanner noise** and provide **objective merge decisions**
in CI/CD pipelines by introducing a policy-driven security score between scanners and Pull Requests.

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
Commercial use requires explicit permission from the author.