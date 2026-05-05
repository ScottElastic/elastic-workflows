# Threat-intel workflows

Scheduled feed ingestion + active environment hunting. Each run fetches a feed, extracts IOCs with AI, hunts the IOCs across `logs-*`, indexes structured findings into `threat-intel-findings`, and creates a briefing case.

| Workflow | Trigger | Notes |
|----------|---------|-------|
| [`elastic-security-labs-feed.yaml`](elastic-security-labs-feed.yaml) | scheduled (24h) / manual | Pulls Elastic Security Labs RSS, runs `platform.core.execute_esql` from the AI agent to hunt the IOCs, posts findings to a case, indexes structured docs to `threat-intel-findings` for the dashboard. Replace `consts.kibana_base_url`, `consts.es_url`, `consts.es_auth`. |
| [`threat-intel-feed-monitor.yaml`](threat-intel-feed-monitor.yaml) | scheduled / manual | Generic feed-monitoring template. Adapt to any RSS / JSON / TAXII source by changing the `fetch_feed` step. |

## `dashboard/` — index mapping + Kibana dashboard

The findings index has a stable schema (`@timestamp`, `feed.*`, `threat.*`, `exposure.*`, `ioc.*`, `mitre.*`, `affected_hosts`, `data_sources`, `detection_gaps`, `action_items`, optional `case.*`). The supplied dashboard surfaces:

- exposure-level distribution
- threats by severity over time
- blind-spot tracker (tech with no telemetry)
- detection-gap list
- action items by priority

### Deploy

```bash
cd workflows/threat-intel/dashboard

export KIBANA_URL="https://YOUR-DEPLOYMENT.kb.REGION.PROVIDER.elastic-cloud.com"
export KIBANA_API_KEY="<base64 id:api_key>"   # preferred
# or:
# export KIBANA_USERNAME="..." KIBANA_PASSWORD="..."

./deploy-dashboard.sh
```

`deploy-dashboard.sh` creates the `threat-intel-findings` index (if missing) using `findings-index-mapping.json`, then imports the dashboard via the Kibana saved-objects API.

### Seed sample data (optional)

```bash
export ES_URL="https://YOUR-DEPLOYMENT.es.REGION.PROVIDER.elastic-cloud.com"
export ES_API_KEY="<base64 id:api_key>"   # preferred
./seed-sample-data.sh
```

This indexes a small set of historical findings so the dashboard isn't empty before the workflow has run.

## API key permissions

The connector / API key used by these workflows needs:

- `index`, `write` on `threat-intel-findings*`
- `read` on `logs-*` (to run `_query` for IOC hunting)
- `manage` on `threat-intel-findings*` if you want the workflow to create the index automatically
