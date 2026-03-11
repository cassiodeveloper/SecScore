![CI](https://github.com/cassiodeveloper/secscore/actions/workflows/ci.yml/badge.svg)
![GitHub release](https://img.shields.io/github/v/release/cassiodeveloper/secscore)
![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![GitHub Action](https://img.shields.io/badge/github-action-ready)

# SecScore

🇺🇸 [English](README.md) | 🇧🇷 Português

**A pontuação de segurança que importa.**

```
Scanner de Segurança
       ↓
      SARIF
       ↓
    SecScore
       ↓
 PASS / REVIEW / FAIL
```

SecScore é um motor leve de pontuação de segurança para pipelines CI/CD.
Ele avalia findings gerados por scanners de segurança e calcula **uma pontuação única de segurança para um Pull Request**, permitindo que equipes decidam automaticamente se a mudança deve **PASSAR, exigir REVISÃO ou FALHAR**.

A ferramenta é agnóstica a scanners e funciona com **SARIF**, sendo compatível com a maioria das ferramentas modernas de segurança.

---

## Por que SecScore

Scanners de segurança geram findings.
Mas pipelines precisam de **decisões**.

```
Scanner → Findings → SecScore → Score → Decisão

Score: 82 / 100
Decisão: REVIEW
```

---

## Principais Recursos

- Pontuação de segurança para Pull Requests
- Regras de hard fail para vulnerabilidades críticas
- Compatível com SARIF (Snyk, CodeQL, Semgrep, Checkmarx, etc.)
- Suporte a múltiplos SARIFs — passe saídas de vários scanners em uma única execução
- Filtro diff-aware — avalia apenas findings introduzidos no PR
- Supressão por fingerprint — suprima falsos positivos confirmados de forma rastreável
- Pronto para GitHub Actions
- Decisões baseadas em policy
- Leve e rápido
- Open source

---

## Como Funciona

```
Scanner de Segurança
       ↓
      SARIF
       ↓
  Parser do SecScore
       ↓
  Motor de Policy
       ↓
 Cálculo de Score
       ↓
 PASS / REVIEW / FAIL
```

Scanners suportados:

- [x] Snyk
- [x] Semgrep
- [x] CodeQL
- [x] Checkmarx
- [x] Trivy
- [x] Qualquer scanner compatível com SARIF

## Entradas Suportadas

| Scanner       | Formato      |
|---------------|--------------|
| Snyk          | SARIF        |
| CodeQL        | SARIF        |
| Semgrep       | SARIF        |
| Checkmarx     | SARIF        |
| Checkmarx API | JSON         |

---

## Instalação

Clone o repositório:

```
git clone https://github.com/cassiodeveloper/secscore
cd secscore
```

Instale as dependências:

```
pip install -r requirements.txt
```

---

## Executando Localmente

Arquivo SARIF único:

```
python -m secscore.cli.main pr \
  --sarif examples/example-snyk.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

M�ltiplos arquivos SARIF (v0.3.0+):

```
python -m secscore.cli.main pr \
  --sarif semgrep.sarif,trivy.sarif \
  --policy policy/policy-pr.yml \
  --no-diff-aware
```

> **Nota:** use `--no-diff-aware` ao rodar localmente sem histórico git completo.
> Em CI, o filtro diff-aware é ativado por padrão e requer `fetch-depth: 0` no passo de checkout.

Saída esperada:

```
Score: 85 / 100
Decisão: PASS
```

---

## GitHub Action

Exemplo mínimo:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: results.sarif
```

M�ltiplos scanners (v0.3.0+):

```yaml
- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: "semgrep.sarif,trivy.sarif"
```

Desativar diff-aware:

```yaml
- name: Run SecScore
  uses: cassiodeveloper/secscore@v1
  with:
    sarif: results.sarif
    no_diff_aware: "true"
```

---

## Segurança Orientada por Policy

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

### Suprimindo falsos positivos por fingerprint (v0.3.0+)

```yaml
suppressions:
  deny_fingerprints:
    - "abc123def456"   # falso positivo confirmado — XSS em helper de testes
```

Obtenha o fingerprint em `secscore-result.json > hard_fails[].finding_fingerprint`.

---

## Exemplos

Arquivos SARIF de exemplo:

```
examples/
  example-snyk.sarif
  example-checkmarx.sarif
```

Workflows de exemplo:

```
examples/workflows/
  example-minimal.yml
  example-snyk.yml
  example-checkmarx.yml
  example-checkmarx-api.yml
  example-multi-scanner.yml
```

---

## Estrutura do Projeto

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

## Segurança

Caso você encontre uma vulnerabilidade neste projeto, reporte de forma responsável.

[SECURITY.md](SECURITY.md)

---

## Contribuição

Contribuições são bem-vindas. Leia primeiro:

[CONTRIBUTING.md](CONTRIBUTING.md)

---

## Licença

Este projeto é licenciado sob a **PolyForm Noncommercial License 1.0.0**.

Uso não-comercial é livre. Uso comercial — incluindo incorporação em produto,
serviço ou plataforma pagos — requer permissão explícita do autor.

[LICENSE](LICENSE) · [polyformproject.org/licenses/noncommercial/1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/)

---

## Filosofia

Scanners de segurança geram ruído.

O SecScore foca no que realmente importa:

**decisões de segurança claras e automatizadas em pipelines CI/CD.**