# Handoff

Context for a fresh session picking up this work. Skim, don't re-derive what you can read in the code.

## Current state

- 165 Splunk SOAR playbooks translated to Elastic Workflows YAML under `workflows/splunk-soar/`. All committed on `main`. PRs #1–#11 merged.
- **All 165 workflows pass Kibana import validation** (PR #11). Previously 36/165 were failing HTTP 400 "Workflow is not valid." at import time — all fixed.
- Test harness in `scripts/test-harness/`: `llm_mock_server.py` (Bedrock-backed, context-aware with indicator extraction), `import_workflows.py`, `run_workflows.py` (schema-aware `build_inputs()` for per-workflow input types).
- Fix pipeline at `scripts/fix_validation_errors.py` — 39 named repair passes. Re-run any time after editing workflow YAMLs.
- **Last full import run (v4, post-PR #11)**: `165 imported, 0 failed` — confirmed against `scotth-9-8e23db.kb.us-west2.gcp.elastic-cloud.com`.
- **Last full execution run (v6, pre-PR #11)**: 66/165 (40%) execute cleanly end-to-end. The 36 import failures are now fixed; re-running execution is the next step to establish a new baseline.

## Key decisions & rationale

- **LLM-backed mock over static mock.** Static returns identical JSON forever, so branching logic only exercises one path. The LLM synthesizes a mix of benign/suspicious entries per request. Cache keyed by `(method, path, query, body)` keeps reruns deterministic and near-free after first hit.
- **Sed-rewrite into `/tmp/workflows-mocked/` instead of editing the repo.** The repo's `workflows/` directory is canonical — adding env-specific ngrok URLs (which rotate) would pollute it. Rebuild command: `find workflows/splunk-soar -name '*.yaml' | while read f; do rel="${f#workflows/splunk-soar/}"; dst="/tmp/workflows-mocked/$rel"; mkdir -p "$(dirname "$dst")"; sed "s|CHANGEME-[a-z0-9-]*\.internal|<ngrok-host>|g" "$f" > "$dst"; done`
- **`fix_validation_errors.py` as a pipeline of named passes.** Each fixer is independent and idempotent. Order matters (structural repairs before filter rewrites); the pipeline applies all passes to each file once. Easy to add/debug individual passes without touching others.
- **API key bootstrapped via Elasticsearch `_security/api_key` on `.es.` URL**, not Kibana `/api/security/api_key`. The Kibana path 404s on this deployment.
- **30-day API key expiration** (current key in `/tmp/soar-fetch/api_key_v2.json`). 24h key was too short for iterative debugging.
- **foreach syntax**: top-level `foreach: "${{ expr }}"` key on the step — NOT nested `with: { items: ... }`.

## Rejected approaches

- **`POST /api/workflows/_bulk_delete`** — 404. Loop individual DELETEs.
- **`?limit=500` on workflow list** — 400. Use pagination (default page size = 100).
- **`/api/workflows/{id}/_execute`** — 404. Real endpoint: `POST /api/workflows/workflow/{id}/run`.
- **`/api/security/api_key` on Kibana URL** — 404. Use ES endpoint on `.es.` URL.
- **`connector-id: "{{ consts.X }}"` flagged as invalid** — actually valid; Kibana resolves template expressions at import time. Confirmed by passing files using this pattern. Do not "fix" these.
- **`delay: "{{ consts.X }}s"` in on-failure** — NOT valid at import time. Must be a literal like `"30s"`. The `repair_delay_template` pass in fix_validation_errors.py resolves these from the file's `consts:` block.
- **`timeout:` on `ai.prompt` steps** — not a valid property. Removed by `repair_ai_prompt_timeout`.
- **`type: scheduled` trigger** — wrong; correct value is `type: schedule`. Fixed by `fix_scheduled_trigger`.
- **Real vendor free-tier accounts** for ground-truth testing. Considered, deferred — mock-everything is faster to iterate. Worth revisiting for flagship demo workflows later.

## Known issues / TODOs

**Execution failures (from v6 run, baseline pre-PR #11 — re-run needed to get current numbers):**
- 7× auth_401: Azure AD × 2, CrowdStrike OAuth × 3, Microsoft Defender × 2 — need real OAuth credentials or per-vendor mock endpoints; deferred
- 5× foreach_type: `steps.X.output.users/.value/.Answer` resolves to undefined. Root cause: the sed URL rewrite replaces the full URL const including path, so `graph_base: https://graph.microsoft.com/v1.0` becomes `https://<ngrok>` losing `/v1.0`. The mock then receives `/v1.0/users` at a path it doesn't recognize. Fix: preserve path suffix in sed, or handle path-prefixed variants in mock_server.py.
- 2× indicators schema: `risk-notable-enrich` and `risk-notable-review-indicators` — Kibana internal validator rejects indicator element objects. Try `{"cef_value": "...", "data_types": "ip"}` (string, not array for `data_types`).
- 3× other: gmail-message-eviction (404 from non-mock URL), splunk-enterprise-security-close-investigation (undefined input value), create-ticket (Liquid render error on empty indicators)
- 1× placeholder DNS: panorama-outbound-traffic-filtering (ENOTFOUND on `changeme-panorama.example.com` — didn't get a CHANGEME-*.internal hostname, so sed didn't rewrite it)
- 1× unknown: servicenow-related-tickets-search (empty error)

**Other:**
- **`elastic-workflows-reference.md` not updated.** foreach example still shows wrong syntax. Common gotchas (Liquid filter set, connector type namespacing, condition quoting, ai.prompt connector requirement) not documented.
- **`scripts/validator/validate.py` is static-only.** Doesn't call `POST /api/workflows/validate` — misses runtime issues.
- **Workflow names display as "Untitled workflow"** in Kibana UI. Cosmetic — name field in the import body doesn't appear to be respected.
- **Mock cache is cold after LLM mock server rewrite.** First execution run will be slow; subsequent runs use `cache/` (gitignored).

## Immediate next steps (priority order)

1. **Re-run execution baseline** with all 165 now passing import. `python3 scripts/test-harness/run_workflows.py --in /tmp/soar-fetch/imported_v4.json`. The 36 newly-fixed workflows will add new execution data. Expect to find new failure modes.
2. **Fix foreach_type failures** — update sed rebuild to preserve path components in base URL consts. Change `s|CHANGEME-[a-z0-9-]*\.internal|<ngrok>|g` to target scheme+host only, leaving the path intact.
3. **Fix panorama placeholder** — `changeme-panorama.example.com` wasn't caught by the sed pattern. Either change the source YAML to use `CHANGEME-panorama.internal` (consistent with other files) or add it explicitly to the sed command.
4. **Debug indicators schema** for risk-notable-enrich / risk-notable-review-indicators. Try alternate element shape, then capture full error via `POST /api/workflows/validate`.
5. **Extend `scripts/validator/validate.py`** with `--api` flag that POSTs to `/api/workflows/validate`. Prevents future regressions.
6. **Update `elastic-workflows-reference.md`** with: correct foreach syntax, condition quoting rules (`'{{ var }}' == 'value'`), unsupported Liquid filters, connector type namespacing, ai.prompt connector requirement, on-failure placement rules.

## Env / state to know

- **User**: Scott Holt, Elastic employee (scott.holt@elastic.co)
- **Kibana**: `https://scotth-9-8e23db.kb.us-west2.gcp.elastic-cloud.com`
- **API key (current)**: `/tmp/soar-fetch/api_key_v2.json` — 30d, name `soar-qa-harness-v2`, expires ~2026-07-02. Use `jq -r .encoded` for the `Authorization: ApiKey` value.
- **ngrok URL** at time of writing: `https://reserveless-augusta-nonaccordantly.ngrok-free.dev` (free-tier — changes on ngrok restart; rebuild `/tmp/workflows-mocked/` and reimport if it changes)
- **AWS Bedrock**: authenticated via user's default boto3 chain. Model `us.anthropic.claude-sonnet-4-5-20250929-v1:0` in `us-west-2`. Env-overridable.
- **Mock cache**: `cache/` in repo root (gitignored)
- **Workflow ID mapping**: `/tmp/soar-fetch/imported_v4.json` (path → id, current as of PR #11 merge)
- **Last execution results**: `/tmp/soar-fetch/results_all.json` (v6 run, pre-PR #11 — stale for the 36 newly fixed workflows)
- **Mocked workflow copy**: `/tmp/workflows-mocked/` (165 files with ngrok URLs substituted in)

## Trustworthy API patterns

- Import body: `{"workflows": [{"yaml": "<text>"}]}`
- Import response: `{"created": [{"id": "...", ...}], "failed": []}`
- Run: `POST /api/workflows/workflow/{id}/run` with `{"inputs": {...}}`
- Run response: `{"workflowExecutionId": "<uuid>"}` (acceptance, not completion)
- Execution detail: `GET /api/workflows/executions/{exec_id}` — `.status` is truth, `.error.message` for failures, `.stepExecutions` for per-step
- Delete: `DELETE /api/workflows/workflow/{id}` (no bulk endpoint)
- List: `GET /api/workflows?page=N` (size=100, no limit param)
