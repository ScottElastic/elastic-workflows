# Test harness — bulk QA the workflows

A zero-dependency local stack for exercising every workflow in this repo
against canned vendor responses. Lets you import → trigger → report on all
165 workflows in a single loop without signing up for a single vendor
account.

## Pieces

| File | What it does |
|---|---|
| `mock_server.py` | Single-process HTTP server that answers for every vendor URL the workflows call (Microsoft Graph, CrowdStrike Falcon, ServiceNow, VirusTotal, Splunk REST, GreyNoise, Recorded Future, Cisco Umbrella, Panorama, Zscaler, AWS, GCP, ReversingLabs, Carbon Black, Vectra, ExtraHop, …) with realistic canned JSON. Catchall returns 200 for anything not specifically handled. |
| `import_workflows.py` | POSTs every `.yaml` under a directory to a Kibana space's `/api/workflows` endpoint. Writes `imported.json` mapping path → assigned workflow id. |
| `run_workflows.py` | Reads `imported.json` and triggers each workflow via `/api/workflows/workflow/{id}/run` with a generic input bundle. Writes `results.json`. |

## Prereqs

- Python 3 (stdlib only — no `pip install`).
- A Kibana instance with the Workflows tech preview enabled. Easiest:
  Elastic Cloud Serverless (Security) — 14-day free trial.
- Optional but recommended: `cloudflared` or `ngrok` to expose your local
  mock server to Elastic Cloud:

  ```bash
  cloudflared tunnel --url http://localhost:8080
  # Prints a https://<random>.trycloudflare.com URL — use that as MOCK_BASE below.
  ```

## End-to-end flow

### 1. Spin up the mock server

```bash
python3 scripts/test-harness/mock_server.py --port 8080
# Logs every request to stderr — useful for debugging which step calls what.
```

Smoke-test it:

```bash
curl -s http://localhost:8080/v1.0/users/test@example.com | jq
curl -s -X POST http://localhost:8080/oauth2/token | jq
curl -s http://localhost:8080/api/v3/files/$(python3 -c 'print("0"*64)') | jq .data.attributes.last_analysis_stats
```

### 2. Point your workflows at the mock

Two options:

**Option A — sed-replace the consts inline.** Pick a tunnel/local URL and
substitute every `CHANGEME-...` endpoint:

```bash
export MOCK_BASE="https://your-tunnel.trycloudflare.com"

# example: replace common endpoint placeholders
find workflows/splunk-soar -name '*.yaml' -exec \
  sed -i.bak -E "s#https://[^\"']*CHANGEME[^\"']*#$MOCK_BASE#g" {} \;
```

**Option B — wire one vendor at a time.** Open a workflow, change its
`consts.*_endpoint:` to `http://localhost:8080` (or your tunnel URL), then
import and run that single workflow. Iterate.

### 3. Set Kibana credentials

```bash
export KIBANA_URL="https://YOUR-DEPLOY.kb.REGION.PROVIDER.elastic-cloud.com"
export KIBANA_API_KEY="<base64 id:api_key>"
```

Create the API key in **Kibana → Stack Management → API keys**. Needs:
- `workflows-all` (or equivalent) for create/run.

### 4. Bulk import

```bash
python3 scripts/test-harness/import_workflows.py \
  --dir workflows/splunk-soar \
  --space default \
  --out imported.json
```

Expected output: `165 imported, 0 failed. Mapping written to imported.json.`

### 5. Bulk run

```bash
python3 scripts/test-harness/run_workflows.py \
  --mapping imported.json \
  --space default \
  --out results.json
```

Filter to a subset:

```bash
python3 scripts/test-harness/run_workflows.py --filter "reputation-analysis/"
```

Each workflow gets the canned input bundle in `run_workflows.py` (user, ip,
url, hash, hostname, etc.). Workflows pull whatever they declare in their
`inputs:` and ignore the rest.

### 6. Read the report

`results.json` maps each YAML path to its HTTP response. Use jq for a
pass/fail summary:

```bash
jq 'to_entries | group_by(.value.status >= 200 and .value.status < 300) | map({pass: .[0].value.status >= 200, count: length})' results.json
```

## Limits — read before believing the green checks

- **The mock returns canned data, not real vendor data.** A workflow may
  trigger end-to-end against the mock and still fail in production because
  the real API's response shape (or pagination behavior, or rate limit) is
  different. The mock proves the workflow *structure* works, not the
  semantics.
- **Alert-triggered workflows lose the `event.*` context** when run via
  `_execute`. To test those properly, you need a real detection rule
  firing into the workflow. Use the sample-data skill in this conversation
  to generate alerts that match each workflow's expected schema.
- **Sub-workflow chains.** Workflows that POST to `/api/workflows/{id}/run`
  will try to call Kibana. Either run them in a space where the child
  workflows have been imported too, or override `workflow_runner_endpoint`
  to point at the mock (catchall returns 200).
- **Auth not enforced.** The mock does not validate `Authorization`
  headers. Production calls will. Test auth wiring separately by hitting
  the real vendor API once with `curl`.

## Next steps after this lands

- Pick 3-5 flagship workflows, replace the mock endpoint with the real
  vendor's free-tier API (VirusTotal community key, ServiceNow Developer
  Instance, Atlassian Jira free, GreyNoise community), and re-run.
- Build a demo deck around the chains: e.g., alert fires → triage
  workflow → enrichment workflow → ticketing workflow.

Use `python3 scripts/validator/validate.py workflows/splunk-soar/` to
check structural validity before each round of edits.
