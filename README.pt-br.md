
# SecScore

🇺🇸 [English](README.md) | 🇧🇷 Português

**A pontuação de segurança que importa.**

SecScore é um motor leve de pontuação de segurança para pipelines CI/CD.  
Ele avalia findings gerados por scanners de segurança e calcula **uma pontuação única de segurança para um Pull Request**, permitindo que equipes decidam automaticamente se a mudança deve **PASSAR, exigir REVISÃO ou FALHAR**.

A ferramenta é agnóstica a scanners e funciona com **SARIF**, sendo compatível com a maioria das ferramentas modernas de segurança.

---

## Por que SecScore

Scanners de segurança geram findings.  
Mas pipelines precisam de **decisões**.

Fluxo:

Scanner → Findings → SecScore → Score → Decision

Exemplo:

Score: 82 / 100  
Decision: REVIEW

---

## Principais Recursos

- Score de segurança para Pull Requests
- Regras de hard fail para vulnerabilidades críticas
- Compatível com SARIF (Snyk, CodeQL, Semgrep, Checkmarx, etc.)
- Pronto para GitHub Actions
- Decisões baseadas em policy
- Leve e rápido
- Open source

---

## Como Funciona

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

---

## Scanners Suportados

| Scanner | Formato |
|-------|-------|
| Snyk | SARIF |
| CodeQL | SARIF |
| Semgrep | SARIF |
| Checkmarx | SARIF |
| Checkmarx API | JSON |

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

Exemplo usando um SARIF de teste:

```
python -m secscore.cli.main pr   --sarif examples/example-snyk.sarif   --policy policy/policy-pr.yml
```

Saída esperada:

```
Score: 85 / 100
Decision: PASS
```

---

## GitHub Action

Exemplo de workflow:

```yaml
name: SecScore PR

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  secscore:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run SecScore
        uses: cassiodeveloper/secscore@v1
        with:
          sarif: results.sarif
```

---

## Segurança

Caso você encontre uma vulnerabilidade neste projeto, reporte de forma responsável.

Veja:  
SECURITY.md

---

## Contribuição

Contribuições são bem‑vindas.

Leia primeiro:

CONTRIBUTING.md

---

## Licença

Este projeto é licenciado sob a MIT License.

[LICENÇA](LICENSE)