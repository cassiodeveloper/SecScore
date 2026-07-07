# Changelog

All notable changes to SecScore will be documented in this file.

The format is based on semantic versioning and follows a simple chronological release history.

---

## v0.5.0 — 2026-07

### Added

* Console entry point for installed environments:
  `secscore pr ...` can now be used instead of `python -m secscore.cli.main pr ...`.
* Optional HTML report output generated from the standard JSON result:
  `--html-output true` and `--html-out secscore-report.html`.
* GitHub Action inputs `html_output` and `html_out` for publishing the visual report as a workflow artifact.
* HTML report polish: dark/light toggle, risk summary, linked findings and artifacts,
  copy JSON path action, collapsible execution parameters, and report footer metadata.
* Optional **M.A.R.I.A policy import** with `--maria-import-policy` and `--maria-policy-url`,
  allowing SecScore to sync repository risk policy before scoring.
* M.A.R.I.A risk score model support (`maria_riskscore_v1`) including risk weights,
  application context, and risk profile multipliers.

### Changed

* Package version bumped to `0.5.0`.
* GitHub Action now documents the workflow permissions needed for checks, PR comments,
  and labels.
* CI workflow now declares explicit least-privilege read access with `permissions: contents: read`.
* PR comment renderer now honors the policy `reporting` block
  (`max_findings_in_comment`, `max_reasons`, `include_fields`) instead of always
  falling back to fixed defaults.

### Fixed

* `include_fields` in the policy `reporting` block is now actually applied when
  rendering finding lines (location and metadata fields), instead of being ignored.

### Security

* Hardened M.A.R.I.A outbound requests against server-side request forgery by validating
  URL schemes, rejecting embedded credentials, and blocking local/private/reserved network
  targets by default. Private/local URLs require explicit trusted opt-in with
  `SECSCORE_ALLOW_PRIVATE_MARIA_URLS=true`.
* Hardened CLI and SARIF file handling against uncontrolled path access by resolving paths
  and requiring them to stay inside the current workspace or approved CI roots.
* Hardened the GitHub composite action against code injection by moving input interpolation
  into environment variables and passing CLI arguments through quoted Bash arrays.
* Hardened the PR comment against Markdown injection from untrusted scanner output by
  escaping finding titles, paths and metadata, and percent-encoding link targets.

### Repository

* Added `.gitattributes` enforcing LF line endings so the composite action's Bash steps
  stay valid on Linux runners regardless of contributor OS.
* Ignored generated artifacts (`secscore-report.html`, runtime `policy/policy-maria.yml`,
  `tmp-*`) and stopped tracking `tmp-result.json`.

---

## v0.4.0 — 2026-04

### Added

* **M.A.R.I.A submissions integration** for CI/CD results publishing:
  * New CLI flags: `--maria-url`, `--maria-token`, `--maria-repository-id`, `--maria-strict`
  * Submission metadata flags: `--maria-submission-key`, `--maria-commit-sha`, `--maria-branch-name`,
    `--maria-pipeline-name`, `--maria-pipeline-run-id`, `--maria-pull-request-id`,
    `--maria-started-at-utc`, `--maria-tool-name`, `--maria-cli-version`
  * Automatic metadata fallback from CI environment and git when values are not provided.
* **GitHub Action support for M.A.R.I.A submission fields** via new action inputs:
  `token`, `maria-url`, `maria-token`, `maria-repository-id`, `maria-pull-request-id`.
* New adapter module `secscore.adapters.maria_provider` to isolate outbound submission logic.
* Automated tests for M.A.R.I.A payload mapping and strict-mode failure behavior.

### Changed

* M.A.R.I.A payload now sends explicit `Score` and `Decision` plus severity `Summary`
  (`Critical`, `High`, `Medium`, `Low`) for submission endpoints.
* Package metadata now declares all runtime dependencies used by the CLI (`pyyaml`, `requests`, `rich`).

### Fixed

* Package runtime metadata mismatch where `rich` was used by CLI but not declared in `pyproject.toml`.

---
## v0.3.0 â€” 2026-03

### Added

* **Multi-SARIF support**: `--sarif` now accepts multiple files as a comma-separated list
  (`--sarif semgrep.sarif,trivy.sarif`) or multiple flags. GitHub Action updated accordingly.
  Findings are deduplicated across files by `(ruleId, path, line)`.
* **Diff-aware filtering enabled by default** in PR mode. SecScore now automatically filters
  findings to only those touching lines changed in the PR. Use `--no-diff-aware` to opt out.
  Gracefully degrades (warning, no abort) when not running inside a git repository or when
  the diff returns no changed files.
* **Suppressions by fingerprint**: policy `suppressions.deny_fingerprints` list allows
  suppressing specific known false positives by their finding fingerprint â€” traceable and
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

## v0.2.0 â€” 2026-03

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

## v0.1.0 â€” Initial Release

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
