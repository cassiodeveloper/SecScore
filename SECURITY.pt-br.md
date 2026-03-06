# Política de Segurança

## Versões Suportadas

O SecScore está em desenvolvimento ativo.

Apenas a **versão mais recente do branch `main`** é suportada.
Commits antigos ou forks podem não receber correções de segurança.

---

## Reportando uma Vulnerabilidade

Se você identificar um problema de segurança no SecScore, reporte de forma **responsável**.

**Não abra issues públicas no GitHub para vulnerabilidades de segurança.**

Reporte de forma privada pelo e-mail:

📧 **cassio@cassiobp.com.br**  
(use um assunto descritivo, por exemplo: “SecScore – vulnerabilidade em parsing de YAML”)

Caso o e-mail não esteja disponível:
- Abra uma issue **sem detalhes técnicos**, marque claramente como *Security Issue* e solicite contato privado.

---

## O que incluir no reporte

Inclua, sempre que possível:

- Descrição clara do problema
- Passos para reprodução (PoC, se houver)
- Arquivos ou componentes afetados
- Impacto potencial
- Sugestão de mitigação ou correção (se existir)

Relatórios claros são tratados mais rapidamente.

---

## Política de Divulgação

O SecScore segue **divulgação responsável**:

- Confirmação de recebimento em até **7 dias**
- Análise e avaliação do impacto
- Correção antes de qualquer divulgação pública
- Crédito ao reportante, se desejado

Divulgação pública sem coordenação não é aceita.

---

## Escopo

Dentro do escopo:
- Core do SecScore
- Lógica de scoring e avaliação de policy
- Normalização de findings
- Adaptadores de CI/CD fornecidos pelo projeto

Fora do escopo:
- Ferramentas de terceiros consumidas pelo SecScore
- Configurações incorretas de pipelines
- Policies definidas intencionalmente pelos usuários
- Forks ou versões modificadas

---

## Filosofia

O SecScore existe para **medir risco**, não para escondê-lo.

Problemas de segurança no projeto são tratados como:
- problemas de engenharia
- com transparência
- sem caça às bruxas

Obrigado por ajudar a manter o SecScore confiável.
