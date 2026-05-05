# Elastic Workflows — YAML Schema & API Reference

> **Status:** Tech Preview (available in Elastic 9.x)
> **Docs:** https://www.elastic.co/docs/explore-analyze/workflows
> **GitHub:** https://github.com/elastic/workflows
> **Blog (deep dive):** https://www.elastic.co/search-labs/blog/elastic-workflows-automation
> **Security Labs:** https://www.elastic.co/security-labs/security-automation-with-elastic-workflows

---

## Kibana API — Import / Export Workflows

### Import a single workflow

```bash
curl -X POST "https://KIBANA_URL/api/workflows" \
  -H "kbn-xsrf: true" \
  -H "x-elastic-internal-origin: Kibana" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -d '{"yaml": "'"$(cat workflow.yaml)"'"}'
```

### Import with `jq` (safer for multiline YAML)

```bash
cat workflow.yaml | jq -Rs '{yaml: .}' | \
curl -X POST "https://KIBANA_URL/api/workflows" \
  -H "kbn-xsrf: true" \
  -H "x-elastic-internal-origin: Kibana" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey API_KEY" \
  -d @-
```

### Bulk import (all YAML files in a directory)

```bash
for file in workflows/security/**/*.yaml; do
  echo "Importing: $file"
  cat "$file" | jq -Rs '{yaml: .}' | \
  curl -s -X POST "https://KIBANA_URL/api/workflows" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    -H "Content-Type: application/json" \
    -H "Authorization: ApiKey API_KEY" \
    -d @-
done
```

### Export (not formally documented yet)

As of the current tech preview, there is no published REST API for exporting workflows. The intended model is YAML-as-code: author workflows in `.yaml` files, store in Git, and import via the API above. You can also copy YAML directly from the Kibana YAML editor.

**Potential undocumented endpoints to explore in your deployment:**

```
GET /api/workflows              # List workflows
GET /api/workflows/{id}         # Get a single workflow
DELETE /api/workflows/{id}      # Delete a workflow
```

### Required headers (all Kibana API calls)

| Header | Value |
|--------|-------|
| `kbn-xsrf` | `true` |
| `x-elastic-internal-origin` | `Kibana` |
| `Content-Type` | `application/json` |
| `Authorization` | `ApiKey <base64-encoded-key>` |

### Spaces

If using Kibana Spaces, prefix the API path:

```
POST /s/<space_name>/api/workflows
```

---

## YAML Schema Reference

### Full skeleton

```yaml
# ═══════════════════════════════════════════════════════════════
# METADATA
# ═══════════════════════════════════════════════════════════════
name: "Workflow Name"                 # Required. Human-readable name.
description: "What this workflow does" # Optional. Detailed description.
enabled: true                          # Optional. Default: true.
tags: ["security", "demo"]             # Optional. For organization/filtering.

# ═══════════════════════════════════════════════════════════════
# CONSTANTS — fixed values, don't change between runs
# ═══════════════════════════════════════════════════════════════
consts:
  indexName: "my-index"
  environment: "production"
  alertThreshold: 100
  endpoints:                           # Can be objects/arrays
    api: "https://api.example.com"
    backup: "https://backup.example.com"

# ═══════════════════════════════════════════════════════════════
# INPUTS — parameters that vary per execution
# ═══════════════════════════════════════════════════════════════
inputs:
  - name: environment
    type: string
    required: true
    default: "staging"
    description: "Target environment"
  - name: dryRun
    type: boolean
    default: true

# ═══════════════════════════════════════════════════════════════
# TRIGGERS — when the workflow runs
# ═══════════════════════════════════════════════════════════════
triggers:
  - type: manual                       # On-demand from UI or API

  # - type: scheduled
  #   with:
  #     every: "6h"                     # Simple interval: "1m", "6h", "1d"

  # - type: alert                      # Fires when a detection rule matches.
  #                                    # Link rule → workflow in rule Actions.

# ═══════════════════════════════════════════════════════════════
# SETTINGS — workflow-level defaults
# ═══════════════════════════════════════════════════════════════
settings:
  on-failure:
    retry:
      max-attempts: 2
      delay: "1s"

# ═══════════════════════════════════════════════════════════════
# STEPS — the actions the workflow performs (executed in order)
# ═══════════════════════════════════════════════════════════════
steps:
  - name: step_name            # Required. Unique identifier within workflow.
    type: action.type          # Required. The step type (see catalog below).
    with:                      # Parameters for the action.
      key: value
    on-failure:                # Optional. Step-level error handling.
      retry:
        max-attempts: 3
        delay: "5s"
      continue: true           # Proceed even on failure
      fallback:                # Alternative steps on failure
        - name: notify_failure
          type: slack
          connector-id: "my-slack"
          with:
            message: "Step failed: {{ steps.step_name.error }}"
```

### Required fields

Only two fields are truly required at the top level:

- `name` — human-readable workflow name
- `steps` — at least one step

### Field reference — `inputs`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Parameter name |
| `type` | string | yes | `string`, `boolean`, `number`, etc. |
| `required` | boolean | no | Whether the input must be provided |
| `default` | any | no | Default value if not provided |
| `description` | string | no | Human-readable description |

---

## Template Variables & Expressions

Workflows use **Liquid templating** for dynamic values.

### Syntax

| Syntax | Behavior |
|--------|----------|
| `{{ expression }}` | String output (coerced to string) |
| `${{ expression }}` | Preserves data type (arrays, objects, numbers) |

### Available template variables

| Variable | Description | Example |
|----------|-------------|---------|
| `consts.<name>` | Workflow constants | `{{ consts.indexName }}` |
| `inputs.<name>` | Runtime inputs | `{{ inputs.target_ip }}` |
| `steps.<step_name>.output` | Output of a previous step | `{{ steps.search.output.hits.total }}` |
| `steps.<step_name>.error` | Error from a failed step (in fallback) | `{{ steps.api_call.error }}` |
| `event` | Alert trigger context (full alert doc) | `{{ event.alerts[0].host.name }}` |
| `event.alerts` | Array of alert documents | `{{ event.alerts[0].file.hash.sha256 }}` |
| `event.rule` | Rule metadata (for alert triggers) | `{{ event.rule.name }}` |
| `execution.id` | Current execution ID | `{{ execution.id }}` |
| `workflow.name` | Name of the current workflow | `{{ workflow.name }}` |

### Liquid filters

You can use Liquid filters inline to transform data:

```yaml
message: "Found {{ steps.search.output.values | size }} results"
```

---

## Trigger Types

### Manual

```yaml
triggers:
  - type: manual
```

Run on-demand from the Kibana UI (Run button) or via the API.

### Scheduled

```yaml
triggers:
  - type: scheduled
    with:
      every: "6h"      # Interval: "1m", "6h", "1d", etc.
```

### Alert-driven

```yaml
triggers:
  - type: alert
```

Connected to a detection/alerting rule via the rule's **Actions** settings in Kibana. Receives the full alert context in the `event` variable.

A workflow can have **multiple triggers**.

---

## Step Types Catalog

### Action steps — Elasticsearch

| Type | Description |
|------|-------------|
| `elasticsearch.search` | Search ES indices |
| `elasticsearch.index` | Index a document |
| `elasticsearch.indices.create` | Create an index with mappings |
| `elasticsearch.indices.delete` | Delete an index |
| `elasticsearch.indices.exists` | Check if an index exists |
| `elasticsearch.esql.query` | Run an ES\|QL query |
| `elasticsearch.request` | Generic ES request (method, path, body) |

#### Example: ES|QL query

```yaml
- name: execute_query
  type: elasticsearch.esql.query
  with:
    format: json
    query: "{{ inputs.query }}"
```

#### Example: Search

```yaml
- name: search_alerts
  type: elasticsearch.search
  with:
    index: ".alerts-security*"
    size: 10
    query:
      term:
        host.name: "{{ inputs.hostname }}"
```

#### Example: Generic request (bulk)

```yaml
- name: bulk_index
  type: elasticsearch.request
  with:
    method: POST
    path: "/{{ consts.indexName }}/_bulk"
    query:
      refresh: "wait_for"
    headers:
      Content-Type: "application/x-ndjson"
    body: |
      {"index":{}}
      {"name":"Document 1","status":"active"}
      {"index":{}}
      {"name":"Document 2","status":"pending"}
```

### Action steps — Kibana

| Type | Description |
|------|-------------|
| `kibana.createCaseDefaultSpace` | Create a Security case |
| `kibana.SetAlertsStatus` | Update alert status |
| `kibana.addCaseComment` | Add comment to a case |
| `kibana.request` | Generic Kibana API request |

Named Kibana actions are available via the **Actions menu → Kibana** in the YAML editor. For anything not covered by a named action, use `kibana.request`.

#### Example: Create a case

```yaml
- name: create_case
  type: kibana.createCaseDefaultSpace
  with:
    title: "Suspicious Login Detected"
    description: "Host '{{ event.alerts[0].host.name }}' exhibited unusual activity."
    tags: ["workflow", "automated-response"]
    severity: "critical"
    connector:
      id: "none"
      name: "none"
      type: ".none"
```

#### Example: Generic Kibana request

```yaml
- name: get_dashboard
  type: kibana.request
  with:
    method: GET
    path: "/api/saved_objects/dashboard/my-dashboard-id"
```

> **Note:** You do not need to pass an `Authorization` header — the workflow engine attaches auth automatically.

### Action steps — External / Connectors

| Type | Description |
|------|-------------|
| `http` | Generic HTTP request (any API, webhook) |
| `slack` | Send Slack message (requires `connector-id`) |
| `virustotal.scanFileHash` | VirusTotal hash lookup |
| Various connectors | Jira, ServiceNow, PagerDuty, Teams, email, Tines, TheHive, etc. |

39+ workflow-compatible connectors including: VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLVoid, AlienVault OTX, Jira, ServiceNow, Slack, Teams, PagerDuty, email, Tines, Resilient, Swimlane, TheHive.

#### Example: HTTP request

```yaml
- name: api_call
  type: http
  with:
    url: "{{ consts.api_url }}/endpoint"
    method: POST
    headers:
      Authorization: "Bearer {{ consts.api_token }}"
    body:
      query: "{{ inputs.search_term }}"
  on-failure:
    retry:
      max-attempts: 3
      delay: 5s
    continue: true
```

#### Example: Slack notification

```yaml
- name: notify_slack
  type: slack
  connector-id: "my-slack-connector"
  with:
    message: "Alert on {{ event.alerts[0].host.name }}: {{ event.rule.name }}"
```

#### Example: VirusTotal

```yaml
- name: check_virustotal
  type: virustotal.scanFileHash
  connector-id: "my-virustotal"
  with:
    hash: "{{ event.alerts[0].file.hash.sha256 }}"
  on-failure:
    retry:
      max-attempts: 2
      delay: 3s
    continue: true
```

### Flow control steps

| Type | Description |
|------|-------------|
| `if` | Conditional branching |
| `foreach` | Iterate over a list |
| `console` | Log a message to execution output |
| `data.set` | Set/store a variable |

#### Example: Conditional

```yaml
- name: check_results
  type: if
  condition: 'steps.search.output.hits.total.value > 0'
  steps:
    - name: log_found
      type: console
      with:
        message: "Found {{ steps.search.output.hits.total.value }} hits"
```

#### Example: data.set

```yaml
- name: store_count
  type: data.set
  with:
    row_count: "{{ steps.execute_query.output.values | size }}"
```

### AI steps

| Type | Description |
|------|-------------|
| `ai.prompt` | Send a prompt to a configured LLM |
| `ai.agent` | Invoke an Elastic Agent Builder agent |

#### Example: AI prompt

```yaml
- name: ai_analysis
  type: ai.prompt
  connector-id: "my-openai"
  with:
    prompt: |
      Analyze the following security alert and provide a risk assessment:
      Host: {{ event.alerts[0].host.name }}
      Rule: {{ event.rule.name }}
      Details: {{ steps.enrich.output | json }}
```

#### Example: Invoke an Agent Builder agent

```yaml
- name: investigate
  type: ai.agent
  with:
    agent-id: "my-security-agent"
    message: "Investigate alert: {{ event.alerts[0] | json }}"
```

---

## Error Handling

### Step-level

```yaml
on-failure:
  retry:
    max-attempts: 3        # Required, minimum 1
    delay: "5s"            # Optional: "5s", "1m", "2h"
  continue: true           # Continue workflow even if step fails
  fallback:                # Alternative steps to run on failure
    - name: notify_failure
      type: slack
      connector-id: "devops-alerts"
      with:
        message: "Failed: {{ steps.failed_step.error }}"
```

### Workflow-level (applies to all steps as default)

```yaml
settings:
  on-failure:
    retry:
      max-attempts: 2
      delay: "1s"
```

Step-level `on-failure` always overrides workflow-level settings.

---

## Data Flow Patterns

### Step chaining

Every step output is stored at `steps.<step_name>.output` and available to all subsequent steps.

```yaml
steps:
  - name: search_user
    type: elasticsearch.search
    with:
      index: ".security-users"
      query:
        match:
          user.name: "{{ inputs.username }}"

  - name: create_case
    type: kibana.createCaseDefaultSpace
    with:
      title: "Investigation: {{ steps.search_user.output.hits.hits[0]._source.user.full_name }}"
      description: "Auto-generated case"
```

### Type-preserving expressions

Use `${{ }}` instead of `{{ }}` when you need to pass arrays or objects (not strings):

```yaml
- name: process_results
  type: some.action
  with:
    data: ${{ steps.query.output.values }}
```

---

## Complete Example — Security Alert Triage

```yaml
name: Alert Triage — VirusTotal + Case Creation
description: >
  Enriches a security alert with VirusTotal, creates a case,
  and notifies the SOC via Slack.
enabled: true
tags: ["security", "triage", "automated"]

triggers:
  - type: alert

consts:
  slack_channel: "soc-alerts"

steps:
  - name: check_virustotal
    type: virustotal.scanFileHash
    connector-id: "my-virustotal"
    with:
      hash: "{{ event.alerts[0].file.hash.sha256 }}"
    on-failure:
      retry:
        max-attempts: 2
        delay: 3s
      continue: true

  - name: ai_triage
    type: ai.prompt
    connector-id: "my-openai"
    with:
      prompt: |
        You are a SOC analyst. Assess this alert:
        Rule: {{ event.rule.name }}
        Host: {{ event.alerts[0].host.name }}
        User: {{ event.alerts[0].user.name }}
        VirusTotal result: {{ steps.check_virustotal.output | json }}
        Provide a severity rating (critical/high/medium/low) and a one-paragraph summary.

  - name: create_case
    type: kibana.createCaseDefaultSpace
    with:
      title: "[Auto] {{ event.rule.name }} — {{ event.alerts[0].host.name }}"
      description: |
        **AI Triage Assessment:**
        {{ steps.ai_triage.output }}

        **VirusTotal:**
        {{ steps.check_virustotal.output | json }}
      tags: ["workflow", "auto-triage"]
      severity: "high"
      connector:
        id: "none"
        name: "none"
        type: ".none"

  - name: notify_soc
    type: slack
    connector-id: "soc-slack"
    with:
      message: |
        🚨 New auto-triaged alert: {{ event.rule.name }}
        Host: {{ event.alerts[0].host.name }}
        AI Assessment: {{ steps.ai_triage.output }}
        Case created.
```

---

## Documentation Links

| Resource | URL |
|----------|-----|
| Workflows overview | https://www.elastic.co/docs/explore-analyze/workflows |
| Get started | https://www.elastic.co/docs/explore-analyze/workflows/get-started |
| Steps reference | https://www.elastic.co/docs/explore-analyze/workflows/steps |
| Kibana action steps | https://www.elastic.co/docs/explore-analyze/workflows/steps/kibana |
| Data & error handling | https://www.elastic.co/docs/explore-analyze/workflows/data |
| Triggers | https://www.elastic.co/docs/explore-analyze/workflows/triggers |
| Agent Builder + Workflows | https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/tools/workflow-tools |
| GitHub repo (50+ examples) | https://github.com/elastic/workflows |
| Search Labs blog | https://www.elastic.co/search-labs/blog/elastic-workflows-automation |
| Security Labs blog | https://www.elastic.co/security-labs/security-automation-with-elastic-workflows |
| Announcement blog | https://www.elastic.co/blog/elastic-workflows-technical-preview |

---

*Last updated: March 2026. Elastic Workflows is in tech preview — APIs and schema may change.*
