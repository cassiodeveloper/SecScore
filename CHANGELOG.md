# Changelog

All notable changes to SecScore will be documented in this file.

The format is based on semantic versioning and follows a simple chronological release history.

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

SecScore aims to reduce **security scanner noise** and provide **objective merge decisions** in CI/CD pipelines by introducing a policy-driven security score between scanners and Pull Requests.
