# Elastic Workflows — SOC Automation Examples

A collection of [Elastic Workflows](https://www.elastic.co/docs/explore-analyze/workflows) (Tech Preview, 9.x) used to automate SOC triage, investigation, and threat-intel hunting in Elastic Security.

Each workflow combines ES|QL queries, Kibana case management, and AI agents (via Agent Builder or `COMPLETION` inference) to enrich alerts, hunt across data sources, and produce analyst-ready cases.

> ⚠️ **Tech Preview.** Elastic Workflows is in tech preview as of 9.x — APIs and YAML schema may change. See [`docs/workflows-reference.md`](docs/workflows-reference.md) for a schema/API reference frozen at the time these workflows were authored.

---

## Repository layout

```
elastic-workflows/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── docs/
│   └── workflows-reference.md      # YAML schema + Kibana API reference
└── workflows/
    ├── triage/                     # Alert-driven first-response workflows
    │   ├── alert-fp-triage-activity-summary.yaml
    │   ├── mfa-bombing-triage.yaml
    │   └── risky-user-signin-investigation.yaml
    ├── investigation/              # Deeper, multi-step investigations
    │   ├── litellm-trojan-investigation.yaml
    │   └── okta-aitm-investigation.yaml
    └── threat-intel/               # Feed ingestion + environment hunting
        ├── elastic-security-labs-feed.yaml
        ├── threat-intel-feed-monitor.yaml
        └── dashboard/              # Index mapping + dashboard for findings
            ├── findings-index-mapping.json
            ├── dashboard.json
            ├── dashboard-export.ndjson
            ├── deploy-dashboard.sh
            └── seed-sample-data.sh
```

---

## Workflow catalog

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| [`triage/alert-fp-triage-activity-summary.yaml`](workflows/triage/alert-fp-triage-activity-summary.yaml) | alert / manual | Generic ECS-based false-positive triage. Pulls 15 min of activity for the alert's IP/user, runs ES\|QL `COMPLETION`, then a security AI agent to make a final FP/TP determination. Auto-closes FPs and escalates TPs to a case. |
| [`triage/mfa-bombing-triage.yaml`](workflows/triage/mfa-bombing-triage.yaml) | alert / manual | Triages Okta MFA-bombing alerts: enriches with sign-in history, AI assessment, Slack notification, case creation. |
| [`triage/risky-user-signin-investigation.yaml`](workflows/triage/risky-user-signin-investigation.yaml) | alert / manual | Full-stack Entra ID risky sign-in investigation across `azure.signinlogs`, `azure.auditlogs`, `azure.graphactivitylogs`, `crowdstrike.alert`, `windows.powershell_operational`, `system.security`. Produces AI triage, dashboard tables, hunt queries, six saved searches, and a case. |
| [`investigation/litellm-trojan-investigation.yaml`](workflows/investigation/litellm-trojan-investigation.yaml) | alert / manual | LiteLLM proxy compromise investigation — process tree, network, secret-access exposure, and AI synthesis. |
| [`investigation/okta-aitm-investigation.yaml`](workflows/investigation/okta-aitm-investigation.yaml) | alert / manual | Okta Adversary-in-the-Middle (AiTM) session-hijack investigation. Hunts session reuse, account modifications, and OAuth/API-key creation tied to a compromised session. |
| [`threat-intel/elastic-security-labs-feed.yaml`](workflows/threat-intel/elastic-security-labs-feed.yaml) | scheduled (24h) / manual | Pulls Elastic Security Labs RSS, has the AI agent extract IOCs and hunt the environment via `platform.core.execute_esql`, indexes structured findings into `threat-intel-findings`, and creates a briefing case. |
| [`threat-intel/threat-intel-feed-monitor.yaml`](workflows/threat-intel/threat-intel-feed-monitor.yaml) | scheduled / manual | Generic feed-monitoring template — adapt to any RSS / JSON / TAXII source. |

---

## Prerequisites

- **Elastic Stack 9.3+** with Workflows enabled (Tech Preview).
- **Kibana Spaces** — workflows live in a space; choose where to import them.
- **Detection rules** linked to the alert-triggered workflows via the rule's *Actions* settings.
- **Inference endpoint** (for `COMPLETION`-based steps) — e.g. `.anthropic-claude-4.6-opus-completion`. Verify with `GET _inference/_all`.
- **Agent Builder agent** (for `ai.agent` steps) — e.g. `security.agent_1` or a custom agent with the ES|QL execution tool.
- **Connectors** as needed by individual workflows (Slack, OpenAI, etc.). Wire connector IDs at import time.
- **Data view** for `logs-*` (used by saved-search creation).

---

## Customisation checklist (before importing)

Every workflow uses `consts:` and `inputs:` for environment-specific values. Search each YAML for these placeholders and replace them:

| Placeholder | Replace with |
|-------------|--------------|
| `YOUR-DEPLOYMENT.kb.REGION.PROVIDER.elastic-cloud.com` | Your Kibana base URL (no trailing slash) |
| `YOUR-DEPLOYMENT.es.REGION.PROVIDER.elastic-cloud.com` | Your Elasticsearch URL |
| `CHANGEME` | Kibana base URL — sentinel checked at runtime; leave as-is to skip case-link rendering |
| `YOUR-LOGS-DATA-VIEW-ID` | Data view ID from Stack Management → Data Views |
| `YOUR_BASE64_API_KEY` | Base64-encoded Elasticsearch API key (for direct `_bulk` calls) |
| `YOUR_SLACK_WEBHOOK_URL` | Incoming Slack webhook URL |
| `xoxb-YOUR-SLACK-TOKEN-HERE` | Slack bot token (or move to a Slack connector) |
| `security.agent_1` | The Agent Builder agent ID you want to use |

Connector IDs (`connector-id: "..."`) reference connectors by ID in your space — create the connector first via *Stack Management → Connectors*, then paste its ID into the workflow.

---

## Importing a workflow

```bash
export KIBANA_URL="https://YOUR-DEPLOYMENT.kb.REGION.PROVIDER.elastic-cloud.com"
export KIBANA_API_KEY="<base64 id:api_key>"

cat workflows/triage/risky-user-signin-investigation.yaml \
  | jq -Rs '{yaml: .}' \
  | curl -sS -X POST "$KIBANA_URL/api/workflows" \
      -H "kbn-xsrf: true" \
      -H "x-elastic-internal-origin: Kibana" \
      -H "Content-Type: application/json" \
      -H "Authorization: ApiKey $KIBANA_API_KEY" \
      -d @-
```

Bulk import:

```bash
for f in workflows/**/*.yaml; do
  echo "Importing: $f"
  jq -Rs '{yaml: .}' < "$f" \
    | curl -sS -X POST "$KIBANA_URL/api/workflows" \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        -H "Authorization: ApiKey $KIBANA_API_KEY" \
        -d @-
done
```

Spaces: prefix the path with `/s/<space_name>` — e.g. `POST /s/security/api/workflows`.

Full schema and API reference: [`docs/workflows-reference.md`](docs/workflows-reference.md).

---

## Threat-intel dashboard

The threat-intel workflows index findings into a `threat-intel-findings` index. To deploy the index mapping and dashboard:

```bash
cd workflows/threat-intel/dashboard
export KIBANA_URL="https://YOUR-DEPLOYMENT.kb.REGION.PROVIDER.elastic-cloud.com"
export KIBANA_API_KEY="<base64 id:api_key>"
./deploy-dashboard.sh
# Optional: seed sample findings from a previous run
./seed-sample-data.sh
```

---

## Disclaimer

These are example workflows shared as-is. They are not officially supported by Elastic. Review each YAML, queries included, before running against production data. Tune severity thresholds, lookback windows, and AI prompts to your environment.

## License

[Apache 2.0](LICENSE).
