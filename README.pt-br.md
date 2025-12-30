# SecScore

**Security score that decides the merge.**

SecScore analisa os resultados de ferramentas de segurança já existentes
(SAST, SCA, IaC, Container), calcula um **score de risco baseado apenas no delta do PR**
e decide automaticamente:

- PASS → merge liberado
- REVIEW → revisão de segurança obrigatória
- FAIL → merge bloqueado

Sem dashboard.  
Sem vendor lock-in.  
Sem achismo.

---

## Como funciona

1. Um Pull Request é aberto
2. Seu CI roda os scanners de segurança (já configurados)
3. Os resultados são normalizados em `findings.json`
4. O SecScore:
   - avalia apenas riscos **novos no PR**
   - aplica regras de hard-fail
   - calcula um score de 0 a 100
5. O SecScore:
   - comenta o resultado no PR
   - atualiza o status do PR (pass/review/fail)

Branch protection faz cumprir a decisão.

---

## O que o SecScore **não** faz

- Não executa scanners
- Não substitui SAST/SCA/IaC/Container
- Não mostra dashboard
- Não decide por feeling

SecScore decide com base em política explícita.

---

## Entrada

- `findings.json` (schema padronizado)
- `policy-pr.yml` (policy-as-code)

## Saída

- Comentário no PR (explicável)
- Status check (PASS / REVIEW / FAIL)
- Exit code:
  - 0 → PASS
  - 1 → REVIEW
  - 2 → FAIL

---

## Exemplo de comentário no PR

