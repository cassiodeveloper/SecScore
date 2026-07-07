# Lição: o comentário de PR ignora `reporting` da policy (defaults 5/3 fixos)

Resumo: [CORRIGIDO 2026-07-07] `render_pr_comment` não honrava `policy.reporting`
— usava sempre `max_findings=5` / `max_reasons=3`. Agora recebe `policy_config`.

## Correção aplicada (2026-07-07)
`render_pr_comment(result, policy, policy_config=None)` passou a receber o dict
de policy real (via `main.py`), e `_get_reporting_config` lê dele
(`max_findings_in_comment`, `max_reasons`, `include_fields`). `include_fields`
agora efetivamente filtra localização e metadata em `_render_finding_line`.
Além disso, título/path/CVE (input não confiável do scanner) passam por
`_md_escape`/`_md_code`/`_url_encode_path` para evitar injeção de
link/emphasis/code no Markdown do comentário. Testes em `tests/test_reporting.py`.

## Fato original confirmado (2026-07-07)
Em `secscore/core/reporting.py`, `_get_reporting_config(result)` lê
`getattr(result, "policy", None)`. Mas `EngineResult`
(`secscore/core/engine.py`) é um dataclass **sem** campo `policy`, então o
retorno é sempre `None` → cai nos defaults `DEFAULT_MAX_FINDINGS=5` /
`DEFAULT_MAX_REASONS=3`.

Além disso, `render_pr_comment(result, policy=...)` é chamado em
`secscore/cli/main.py` passando `policy` como **string** (caminho do arquivo),
não o dict — então não há como o renderer ler a config mesmo que quisesse.

## Impacto
- `policy-default.yml` define `max_findings_in_comment: 10`, mas o comentário
  mostra no máximo 5 e adiciona "+N additional findings not shown."
- O parâmetro `include_fields` é buscado e repassado a `_render_finding_line`,
  mas **nunca é usado** para filtrar campos (dead param).
- O engine (`_select_findings_to_show`, `_build_reasons`) JÁ respeita a policy;
  a divergência é só na camada de renderização, que trunca de novo com defaults.

## Por que importa
Usuários que ajustam `reporting.max_findings_in_comment` na policy esperam ver
o efeito no comentário de PR — hoje é silenciosamente ignorado. É um bug de
comportamento (não de segurança), baixa severidade, mas quebra a expectativa
"policy é a fonte de verdade".

## Como corrigir (quando autorizado)
Passar o dict de policy real para `render_pr_comment` e ler `policy["reporting"]`
diretamente, OU adicionar `policy`/`reporting` ao `EngineResult`. Ajustar/─adicionar
teste em `tests/` cobrindo `max_findings_in_comment` != 5.
