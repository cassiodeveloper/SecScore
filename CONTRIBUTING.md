# Contributing to SecScore

Thanks for your interest in contributing to SecScore.

SecScore is a technical, opinionated project focused on **measuring security risk clearly and honestly**.
Contributions are welcome as long as they respect that goal.

---

## Project Principles

Before contributing, please understand what SecScore is — and is not.

SecScore:
- measures security risk
- produces explainable scores
- focuses on Pull Requests and deltas
- remains CI-first and vendor-agnostic

SecScore does NOT:
- run scanners
- provide dashboards
- hide logic behind abstractions
- make decisions on behalf of users

If a contribution conflicts with these principles, it will not be accepted.

---

## How to Contribute

### 1. Report bugs or suggest improvements
- Open a GitHub Issue
- Be clear and concise
- Include:
  - expected behavior
  - actual behavior
  - relevant logs or examples
  - sample `findings.json` if applicable

Avoid vague feature requests.

---

### 2. Propose changes before large work
For non-trivial changes:
- open an Issue first
- describe the problem you are solving
- explain why it fits SecScore’s scope

This avoids wasted effort.

---

### 3. Code Contributions

#### Workflow
1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Submit a Pull Request

Keep PRs small and focused.

---

## Coding Guidelines

- Prefer **clarity over cleverness**
- Avoid unnecessary abstractions
- Keep logic explicit and readable
- Favor deterministic behavior
- No hidden side effects

SecScore is a decision instrument.  
Predictability matters more than flexibility.

---

## Policies and Schemas

- Changes to `policy-pr.yml` or scoring logic must:
  - be backward-compatible when possible
  - include a clear rationale
  - avoid breaking existing pipelines silently

- Changes to schemas must:
  - be versioned
  - include migration notes

Breaking changes require discussion.

---

## Tests

At minimum, contributions should include:
- example inputs (`findings.json`)
- expected outputs (score, decision)

Formal test suites may evolve, but behavior must be demonstrable.

---

## Security Issues

Do **not** report security vulnerabilities via GitHub Issues.

See `SECURITY.md` for responsible disclosure instructions.

---

## Code of Conduct

Be professional.

We value:
- technical clarity
- respectful disagreement
- evidence-based discussion

We do not tolerate:
- harassment
- personal attacks
- ideological arguments unrelated to the project

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

## Final Note

SecScore is intentionally small and focused.

If you are looking to add:
- dashboards
- SaaS features
- heavy integrations
- opinionated workflows

please open an issue and discuss first.

Good ideas are welcome.  
Scope creep is not.
