# Contribuindo com o SecScore

Obrigado pelo interesse em contribuir com o SecScore.

O SecScore é um projeto técnico e intencionalmente opinativo, focado em
**medir risco de segurança de forma clara e honesta**.
Contribuições são bem-vindas desde que respeitem esse objetivo.

---

## Princípios do Projeto

Antes de contribuir, entenda claramente o que o SecScore é — e o que não é.

O SecScore:
- mede risco de segurança
- gera scores explicáveis
- foca em Pull Requests e deltas
- é CI-first e agnóstico de vendor

O SecScore NÃO:
- executa scanners
- fornece dashboards
- esconde lógica atrás de abstrações
- toma decisões no lugar do usuário

Contribuições que conflitem com esses princípios não serão aceitas.

---

## Como Contribuir

### 1. Reportar bugs ou sugerir melhorias
- Abra uma Issue no GitHub
- Seja claro e objetivo
- Inclua:
  - comportamento esperado
  - comportamento atual
  - logs relevantes ou exemplos
  - amostra de `findings.json`, quando aplicável

Evite pedidos vagos.

---

### 2. Propor mudanças maiores
Para mudanças não triviais:
- abra uma Issue antes
- descreva o problema a ser resolvido
- explique por que isso se encaixa no escopo do SecScore

Isso evita retrabalho.

---

### 3. Contribuições de Código

#### Fluxo
1. Faça um fork do repositório
2. Crie um branch a partir do `main`
3. Implemente as mudanças
4. Abra um Pull Request

Mantenha PRs pequenos e focados.

---

## Diretrizes de Código

- Prefira **clareza a esperteza**
- Evite abstrações desnecessárias
- Mantenha a lógica explícita e legível
- Priorize comportamento determinístico
- Evite efeitos colaterais ocultos

O SecScore é um instrumento de decisão.  
Previsibilidade importa mais que flexibilidade.

---

## Policies e Schemas

- Mudanças em `policy-pr.yml` ou na lógica de scoring devem:
  - ser compatíveis com versões anteriores, sempre que possível
  - ter justificativa clara
  - evitar quebrar pipelines silenciosamente

- Mudanças em schemas devem:
  - ser versionadas
  - incluir notas de migração

Mudanças quebrando compatibilidade exigem discussão prévia.

---

## Testes

No mínimo, contribuições devem incluir:
- exemplos de entrada (`findings.json`)
- resultados esperados (score e decisão)

Suites de teste formais podem evoluir, mas o comportamento precisa ser demonstrável.

---

## Problemas de Segurança

Não reporte vulnerabilidades via Issues públicas.

Consulte o arquivo `SECURITY.md` para instruções de divulgação responsável.

---

## Código de Conduta

Seja profissional.

Valorizamos:
- clareza técnica
- discordância respeitosa
- discussões baseadas em evidência

Não toleramos:
- assédio
- ataques pessoais
- debates ideológicos fora do escopo do projeto

---

## Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob a mesma licença do projeto.

---

## Nota Final

O SecScore é intencionalmente pequeno e focado.

Se você pretende adicionar:
- dashboards
- features SaaS
- integrações pesadas
- workflows opinativos

abra uma Issue para discussão antes.

Boas ideias são bem-vindas.  
Escopo descontrolado, não.
