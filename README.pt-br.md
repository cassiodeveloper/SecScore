![CI](https://github.com/cassiodeveloper/secscore/actions/workflows/ci.yml/badge.svg)
![GitHub release](https://img.shields.io/github/v/release/cassiodeveloper/secscore)
![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![GitHub Action](https://img.shields.io/badge/github-action-ready)

# SecScore

🇺🇸 [English](README.md) | 🇧🇷 Português

**A pontuação de segurança que importa.**

SecScore é um motor de decisão de segurança para CI/CD.
Ele transforma findings de scanners em uma decisão objetiva de PR: **PASS / REVIEW / FAIL**.

---

## Principais recursos

- Score de segurança para Pull Requests
- Regras de hard fail para vulnerabilidades críticas
- Compatível com SARIF (Snyk, CodeQL, Semgrep, Checkmarx, Trivy, etc.)
- Suporte a múltiplos SARIFs
- Filtro diff-aware (ativado por padrão)
- Supressão por fingerprint
- Integração opcional com M.A.R.I.A (`/api/secscore/submissions`)
- GitHub Action pronta para uso

---

## Executando localmente

## Quickstart em 5 minutos

1. Execute com SARIF + policy:

```bash
python -m secscore.cli.main pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

2. Confira os artefatos:
- `pr-comment.md` (resumo para comentário de PR)
- `secscore-result.json` (resultado estruturado)

3. Opcional: enviar para M.A.R.I.A:

```bash
python -m secscore.cli.main pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --maria-url http://localhost:5213/api/secscore/submissions \
  --maria-repository-id 11111111-2222-3333-4444-555555555555 \
  --token YOUR_MARIA_TOKEN \
  --no-diff-aware
```

---

## Cenários copiar e colar

Use estes comandos para validar rapidamente os comportamentos esperados:

### PASS

```bash
python -m secscore.cli.main pr \
  --sarif tests/fixtures/pass.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Esperado: `Decision: PASS`

### REVIEW

```bash
python -m secscore.cli.main pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Esperado: `Decision: REVIEW`

### FAIL

```bash
python -m secscore.cli.main pr \
  --sarif tests/fixtures/fail.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Esperado: `Decision: FAIL`

---

## Quando usar cada modo

| Modo | Quando usar | Flags obrigatórias |
|------|-------------|--------------------|
| SARIF (`--sarif`) | Você já gerou SARIF no CI | `--sarif`, `--policy` |
| Findings JSON (`--findings`) | Você já possui findings normalizados em JSON | `--findings`, `--policy` |
| Provider (`--provider checkmarx`) | Você quer que o SecScore busque findings direto da API do provider | `--provider checkmarx`, flags do provider, `--policy` |

---

Exemplo com SARIF:

```bash
python -m secscore.cli.main pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Exemplo com envio para M.A.R.I.A:

```bash
python -m secscore.cli.main pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --maria-url https://demo.mariaappsec.com/api/secscore/submissions \
  --maria-repository-id 11111111-2222-3333-4444-555555555555 \
  --token YOUR_MARIA_TOKEN \
  --no-diff-aware
```

Para `/api/secscore/submissions`, o SecScore envia `Score`, `Decision`, `Summary` e preenche automaticamente metadados de pipeline/commit/branch.

Flags úteis de override:
- `--maria-submission-key`
- `--maria-commit-sha`
- `--maria-branch-name`
- `--maria-pipeline-name`
- `--maria-pipeline-run-id`
- `--maria-pull-request-id`

---

## GitHub Action

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: "semgrep.sarif,trivy.sarif"
    maria-url: "https://demo.mariaappsec.com/api/secscore/submissions"
    maria-repository-id: "11111111-2222-3333-4444-555555555555"
    maria-token: ${{ secrets.MARIA_TOKEN }}
```

---

## Política (policy)

### Policy mínima

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
    reason: "Novo finding SAST crítico/alto"
```

### Policy recomendada (exemplo)

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
    reason: "Novo finding crítico"

ignore_paths:
  - "node_modules/**"
  - "dist/**"
```

---

## Troubleshooting

- `404 Not Found` no M.A.R.I.A: rota incorreta; use `/api/secscore/submissions`.
- `400 Bad Request` no M.A.R.I.A: contrato de payload inválido (campos obrigatórios ausentes/incorretos).
- `401 Unauthorized` no M.A.R.I.A: token inválido para o ambiente.
- `403 Forbidden` no M.A.R.I.A: token válido, mas sem escopo/acesso ao repositório alvo.
- Aviso `Diff-aware skipped`: esperado localmente sem histórico git completo; use `--no-diff-aware`.

---

## Licença

Este projeto usa **PolyForm Noncommercial License 1.0.0**.

[LICENSE](LICENSE)
