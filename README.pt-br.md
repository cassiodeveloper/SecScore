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
secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

2. Confira os artefatos:
- `pr-comment.md` (resumo para comentário de PR)
- `secscore-result.json` (resultado estruturado)
- Opcional: `secscore-report.html` (relatório visual gerado com `--html-output true`)

3. Opcional: enviar para M.A.R.I.A:

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

## Cenários copiar e colar

Use estes comandos para validar rapidamente os comportamentos esperados:

### PASS

```bash
secscore pr \
  --sarif tests/fixtures/pass.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Esperado: `Decision: PASS`

### REVIEW

```bash
secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Esperado: `Decision: REVIEW`

### FAIL

```bash
secscore pr \
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
secscore pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

Gerar também um relatório HTML visual a partir do JSON padrão:

```bash
secscore pr \
  --sarif tests/fixtures/review.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware \
  --html-output true
```

O JSON é sempre gerado. Quando o HTML está ativado, o SecScore também grava
`secscore-report.html` por padrão. Use `--html-out meu-relatorio.html` para escolher outro caminho.

Exemplo com envio para M.A.R.I.A:

```bash
secscore pr \
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

### Comportamento de import de policy do M.A.R.I.A

- Quando a integração com M.A.R.I.A está configurada (`--maria-url`, `--maria-repository-id`, `--token`/`--maria-token`),
  o SecScore importa a policy do M.A.R.I.A por padrão.
- A policy importada é salva em toda execução em `policy/policy-maria.yml`.
- A execução passa a usar `policy/policy-maria.yml` como policy efetiva.
- Use `--maria-import-policy false` para continuar usando a policy local informada em `--policy`.

---

## GitHub Action

Permissões recomendadas no workflow:

```yaml
permissions:
  contents: read
  checks: write
  pull-requests: write
  issues: write
```

O SecScore usa `contents: read` para acessar o repositório, `checks: write` para criar o status check,
e `issues: write`/`pull-requests: write` para atualizar comentários de PR e gerenciar a label de revisão.

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

Gerar e publicar o relatório HTML como artifact do workflow:

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
