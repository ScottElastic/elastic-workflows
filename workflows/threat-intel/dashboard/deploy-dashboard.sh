#!/usr/bin/env bash
# =============================================================================
# Deploy Threat Intel Findings Index + Dashboard
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDEX_NAME="threat-intel-findings"
MAPPING_FILE="$SCRIPT_DIR/threat-intel-findings-index-mapping.json"

# ---------------------------------------------------------------------------
# Connection defaults (override via env vars)
# ---------------------------------------------------------------------------
# Required: KIBANA_URL must be set in your environment.
#   export KIBANA_URL="https://YOUR-DEPLOYMENT.kb.REGION.PROVIDER.elastic-cloud.com"
# Auth — pick ONE of the following:
#   1. KIBANA_API_KEY (recommended): export KIBANA_API_KEY="<base64 id:api_key>"
#   2. KIBANA_USERNAME / KIBANA_PASSWORD (basic auth fallback)
: "${KIBANA_URL:?KIBANA_URL is required (e.g. https://example.kb.us-east-1.aws.elastic-cloud.com)}"
if [[ -z "${KIBANA_API_KEY:-}" ]]; then
  : "${KIBANA_USERNAME:?Set KIBANA_API_KEY, or KIBANA_USERNAME and KIBANA_PASSWORD}"
  : "${KIBANA_PASSWORD:?Set KIBANA_API_KEY, or KIBANA_USERNAME and KIBANA_PASSWORD}"
fi

if [[ -z "${ES_URL:-}" ]]; then
  ES_URL="${KIBANA_URL/.kb./.es.}"
  ES_URL="${ES_URL/:5601/:9200}"
  echo "Derived ES_URL from KIBANA_URL: $ES_URL"
fi

if [[ -n "${KIBANA_API_KEY:-}" ]]; then
  AUTH_HEADER="Authorization: ApiKey $KIBANA_API_KEY"
else
  AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$KIBANA_USERNAME" "$KIBANA_PASSWORD" | base64)"
fi

# ---------------------------------------------------------------------------
# Step 1: Create Elasticsearch index with mappings
# ---------------------------------------------------------------------------
echo "==> Checking if index '$INDEX_NAME' exists..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "$AUTH_HEADER" "$ES_URL/$INDEX_NAME" 2>/dev/null || true)

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "    Index already exists. Updating mappings..."
  curl -s -X PUT -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    "$ES_URL/$INDEX_NAME/_mapping" -d "$(jq '.mappings' "$MAPPING_FILE")" | jq .
else
  echo "    Creating index..."
  curl -s -X PUT -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    "$ES_URL/$INDEX_NAME" -d @"$MAPPING_FILE" | jq .
fi
echo "    Index ready."

# ---------------------------------------------------------------------------
# Step 2: Create dashboard via saved objects API
# ---------------------------------------------------------------------------
echo ""
echo "==> Deploying dashboard..."

# Delete existing dashboard
# Note: v1 dashboard (threat-intel-findings-overview) is left intact.
# This creates v2 alongside it.

# Build the dashboard JSON with panelsJSON as a properly escaped string.
# Uses python3 to avoid shell escaping nightmares with nested JSON.
DASHBOARD_BODY=$(python3 << 'PYEOF'
import json

panels = [
    {
        "type": "lens", "panelIndex": "p1",
        "gridData": {"x": 0, "y": 0, "w": 12, "h": 5, "i": "p1"},
        "embeddableConfig": {"attributes": {
            "title": "Total Threats Tracked", "visualizationType": "lnsMetric", "type": "lens",
            "state": {
                "visualization": {"layerId": "l1", "layerType": "data", "metricAccessor": "c1"},
                "datasourceStates": {"textBased": {"layers": {"l1": {
                    "query": {"esql": "FROM threat-intel-findings | STATS total = COUNT_DISTINCT(threat.name.keyword)"},
                    "columns": [{"columnId": "c1", "fieldName": "total", "meta": {"type": "number"}}],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p2",
        "gridData": {"x": 12, "y": 0, "w": 12, "h": 5, "i": "p2"},
        "embeddableConfig": {"attributes": {
            "title": "Active IOC Hits", "visualizationType": "lnsMetric", "type": "lens",
            "state": {
                "visualization": {"layerId": "l2", "layerType": "data", "metricAccessor": "c2"},
                "datasourceStates": {"textBased": {"layers": {"l2": {
                    "query": {"esql": "FROM threat-intel-findings | WHERE ioc.matched == true | STATS hits = COUNT_DISTINCT(threat.name.keyword)"},
                    "columns": [{"columnId": "c2", "fieldName": "hits", "meta": {"type": "number"}}],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p3",
        "gridData": {"x": 24, "y": 0, "w": 12, "h": 5, "i": "p3"},
        "embeddableConfig": {"attributes": {
            "title": "Critical / Blind Spots", "visualizationType": "lnsMetric", "type": "lens",
            "state": {
                "visualization": {"layerId": "l3", "layerType": "data", "metricAccessor": "c3"},
                "datasourceStates": {"textBased": {"layers": {"l3": {
                    "query": {"esql": "FROM threat-intel-findings | WHERE exposure.level IN (\"critical\", \"blind_spot\") | STATS total = COUNT_DISTINCT(threat.name.keyword)"},
                    "columns": [{"columnId": "c3", "fieldName": "total", "meta": {"type": "number"}}],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p4",
        "gridData": {"x": 36, "y": 0, "w": 12, "h": 5, "i": "p4"},
        "embeddableConfig": {"attributes": {
            "title": "Active Feeds", "visualizationType": "lnsMetric", "type": "lens",
            "state": {
                "visualization": {"layerId": "l4", "layerType": "data", "metricAccessor": "c4"},
                "datasourceStates": {"textBased": {"layers": {"l4": {
                    "query": {"esql": "FROM threat-intel-findings | STATS feeds = COUNT_DISTINCT(feed.name)"},
                    "columns": [{"columnId": "c4", "fieldName": "feeds", "meta": {"type": "number"}}],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p5",
        "gridData": {"x": 0, "y": 5, "w": 16, "h": 12, "i": "p5"},
        "embeddableConfig": {"attributes": {
            "title": "Exposure Level Breakdown", "visualizationType": "lnsPie", "type": "lens",
            "state": {
                "visualization": {"shape": "donut", "layers": [{"layerId": "l5", "layerType": "data", "primaryGroups": ["c5a"], "metrics": ["c5b"], "numberDisplay": "percent"}]},
                "datasourceStates": {"textBased": {"layers": {"l5": {
                    "query": {"esql": "FROM threat-intel-findings | STATS count = COUNT(*) BY exposure.level | SORT count DESC"},
                    "columns": [
                        {"columnId": "c5a", "fieldName": "exposure.level", "meta": {"type": "string"}},
                        {"columnId": "c5b", "fieldName": "count", "meta": {"type": "number"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p6",
        "gridData": {"x": 16, "y": 5, "w": 32, "h": 12, "i": "p6"},
        "embeddableConfig": {"attributes": {
            "title": "Findings Over Time by Exposure Level", "visualizationType": "lnsDatatable", "type": "lens",
            "state": {
                "visualization": {"layerId": "l6", "layerType": "data", "columns": [{"columnId": "c6a"}, {"columnId": "c6b"}, {"columnId": "c6c"}]},
                "datasourceStates": {"textBased": {"layers": {"l6": {
                    "query": {"esql": "FROM threat-intel-findings | STATS count = COUNT(*) BY feed.run_timestamp, exposure.level | SORT feed.run_timestamp DESC"},
                    "columns": [
                        {"columnId": "c6a", "fieldName": "feed.run_timestamp", "meta": {"type": "date"}},
                        {"columnId": "c6b", "fieldName": "exposure.level", "meta": {"type": "string"}},
                        {"columnId": "c6c", "fieldName": "count", "meta": {"type": "number"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p7",
        "gridData": {"x": 0, "y": 17, "w": 48, "h": 14, "i": "p7"},
        "embeddableConfig": {"attributes": {
            "title": "Threat Correlation Matrix", "visualizationType": "lnsDatatable", "type": "lens",
            "state": {
                "visualization": {"layerId": "l7", "layerType": "data", "columns": [{"columnId": "c7a"}, {"columnId": "c7b"}, {"columnId": "c7c"}, {"columnId": "c7d"}, {"columnId": "c7e"}, {"columnId": "c7f"}]},
                "datasourceStates": {"textBased": {"layers": {"l7": {
                    "query": {"esql": "FROM threat-intel-findings | SORT exposure.score DESC | KEEP threat.name.keyword, exposure.level, threat.severity, exposure.score, exposure.notes.keyword, feed.name | LIMIT 50"},
                    "columns": [
                        {"columnId": "c7a", "fieldName": "threat.name.keyword", "meta": {"type": "string"}},
                        {"columnId": "c7b", "fieldName": "exposure.level", "meta": {"type": "string"}},
                        {"columnId": "c7c", "fieldName": "threat.severity", "meta": {"type": "string"}},
                        {"columnId": "c7d", "fieldName": "exposure.score", "meta": {"type": "number"}},
                        {"columnId": "c7e", "fieldName": "exposure.notes.keyword", "meta": {"type": "string"}},
                        {"columnId": "c7f", "fieldName": "feed.name", "meta": {"type": "string"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p8",
        "gridData": {"x": 0, "y": 31, "w": 48, "h": 12, "i": "p8"},
        "embeddableConfig": {"attributes": {
            "title": "Active IOC Matches - Confirmed Hits", "visualizationType": "lnsDatatable", "type": "lens",
            "state": {
                "visualization": {"layerId": "l8", "layerType": "data", "columns": [{"columnId": "c8a"}, {"columnId": "c8b"}, {"columnId": "c8c"}, {"columnId": "c8d"}, {"columnId": "c8e"}]},
                "datasourceStates": {"textBased": {"layers": {"l8": {
                    "query": {"esql": "FROM threat-intel-findings | WHERE ioc.matched == true | SORT exposure.score DESC | KEEP threat.name.keyword, exposure.level, ioc.match_count, threat.severity, feed.name | LIMIT 50"},
                    "columns": [
                        {"columnId": "c8a", "fieldName": "threat.name.keyword", "meta": {"type": "string"}},
                        {"columnId": "c8b", "fieldName": "exposure.level", "meta": {"type": "string"}},
                        {"columnId": "c8c", "fieldName": "ioc.match_count", "meta": {"type": "number"}},
                        {"columnId": "c8d", "fieldName": "threat.severity", "meta": {"type": "string"}},
                        {"columnId": "c8e", "fieldName": "feed.name", "meta": {"type": "string"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p9",
        "gridData": {"x": 0, "y": 43, "w": 24, "h": 12, "i": "p9"},
        "embeddableConfig": {"attributes": {
            "title": "MITRE ATT&CK Technique Coverage", "visualizationType": "lnsDatatable", "type": "lens",
            "state": {
                "visualization": {"layerId": "l9", "layerType": "data", "columns": [{"columnId": "c9a"}, {"columnId": "c9b"}]},
                "datasourceStates": {"textBased": {"layers": {"l9": {
                    "query": {"esql": "FROM threat-intel-findings | MV_EXPAND mitre.technique_ids | WHERE mitre.technique_ids IS NOT NULL | STATS count = COUNT(*) BY mitre.technique_ids | SORT count DESC | LIMIT 20"},
                    "columns": [
                        {"columnId": "c9a", "fieldName": "mitre.technique_ids", "meta": {"type": "string"}},
                        {"columnId": "c9b", "fieldName": "count", "meta": {"type": "number"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p10",
        "gridData": {"x": 24, "y": 43, "w": 24, "h": 12, "i": "p10"},
        "embeddableConfig": {"attributes": {
            "title": "Findings by Threat Type", "visualizationType": "lnsPie", "type": "lens",
            "state": {
                "visualization": {"shape": "donut", "layers": [{"layerId": "l10", "layerType": "data", "primaryGroups": ["c10a"], "metrics": ["c10b"], "numberDisplay": "percent"}]},
                "datasourceStates": {"textBased": {"layers": {"l10": {
                    "query": {"esql": "FROM threat-intel-findings | STATS count = COUNT(*) BY threat.type | SORT count DESC"},
                    "columns": [
                        {"columnId": "c10a", "fieldName": "threat.type", "meta": {"type": "string"}},
                        {"columnId": "c10b", "fieldName": "count", "meta": {"type": "number"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "lens", "panelIndex": "p11",
        "gridData": {"x": 0, "y": 55, "w": 48, "h": 12, "i": "p11"},
        "embeddableConfig": {"attributes": {
            "title": "Detection Gaps & Blind Spots", "visualizationType": "lnsDatatable", "type": "lens",
            "state": {
                "visualization": {"layerId": "l11", "layerType": "data", "columns": [{"columnId": "c11a"}, {"columnId": "c11b"}, {"columnId": "c11c"}, {"columnId": "c11d"}]},
                "datasourceStates": {"textBased": {"layers": {"l11": {
                    "query": {"esql": "FROM threat-intel-findings | WHERE exposure.level IN (\"blind_spot\", \"critical\", \"high\") | SORT exposure.score DESC | KEEP threat.name.keyword, exposure.level, exposure.notes.keyword, feed.name | LIMIT 50"},
                    "columns": [
                        {"columnId": "c11a", "fieldName": "threat.name.keyword", "meta": {"type": "string"}},
                        {"columnId": "c11b", "fieldName": "exposure.level", "meta": {"type": "string"}},
                        {"columnId": "c11c", "fieldName": "exposure.notes.keyword", "meta": {"type": "string"}},
                        {"columnId": "c11d", "fieldName": "feed.name", "meta": {"type": "string"}}
                    ],
                    "timeField": "@timestamp"
                }}}},
                "query": {"query": "", "language": "kuery"}, "filters": []
            }, "references": []
        }, "enhancements": {}}
    },
    {
        "type": "search", "panelIndex": "p12",
        "gridData": {"x": 0, "y": 67, "w": 48, "h": 16, "i": "p12"},
        "panelRefName": "panel_p12",
        "embeddableConfig": {"enhancements": {}}
    }
]

body = {
    "attributes": {
        "title": "Threat Intelligence Findings Overview v2",
        "description": "Live dashboard showing threat correlation, exposure levels, IOC matches, and detection gaps from automated threat intel feeds.",
        "timeRestore": True,
        "timeFrom": "now-30d",
        "timeTo": "now",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": "{}",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {
            "id": "threat-intel-ioc-matches",
            "name": "panel_p12",
            "type": "search"
        }
    ]
}

print(json.dumps(body))
PYEOF
)

echo "    Creating dashboard via saved objects API..."
TMPOUT=$(mktemp /tmp/dashboard-result-XXXXXX.json)
trap "rm -f $TMPOUT" EXIT

HTTP_CODE=$(curl -s -o "$TMPOUT" -w "%{http_code}" \
  -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "$KIBANA_URL/api/saved_objects/dashboard/threat-intel-findings-overview-v2?overwrite=true" \
  -d "$DASHBOARD_BODY")

if [[ "$HTTP_CODE" =~ ^2 ]]; then
  echo "    Dashboard created successfully!"
  echo "    URL: $KIBANA_URL/app/dashboards#/view/threat-intel-findings-overview-v2"
else
  echo "    ERROR: HTTP $HTTP_CODE"
  jq '.' "$TMPOUT" 2>/dev/null || cat "$TMPOUT"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Create data view for threat-intel-findings
# ---------------------------------------------------------------------------
echo ""
echo "==> Creating data view..."
curl -s -o /dev/null -w "" -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "$KIBANA_URL/api/data_views/data_view" \
  -d '{
    "data_view": {
      "id": "threat-intel-findings-dv",
      "title": "threat-intel-findings",
      "timeFieldName": "@timestamp",
      "name": "Threat Intel Findings"
    },
    "override": true
  }' 2>/dev/null || true
echo "    Data view ready."

# ---------------------------------------------------------------------------
# Step 4: Create saved search for Active IOC Matches (Discover link)
# ---------------------------------------------------------------------------
echo ""
echo "==> Creating saved search for Active IOC Matches..."

SAVED_SEARCH_BODY=$(python3 << 'PYEOF2'
import json

body = {
    "attributes": {
        "title": "Active IOC Matches — Threat Intel Findings",
        "description": "All threat intel findings with confirmed IOC matches in the environment. Use this to investigate active hits.",
        "columns": [
            "threat.name",
            "exposure.level",
            "exposure.score",
            "ioc.match_count",
            "threat.severity",
            "data_sources",
            "exposure.notes",
            "feed.name"
        ],
        "sort": [["exposure.score", "desc"], ["@timestamp", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "index": "threat-intel-findings-dv",
                "query": {"query": "ioc.matched : true", "language": "kuery"},
                "filter": []
            })
        }
    },
    "references": [
        {
            "id": "threat-intel-findings-dv",
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern"
        }
    ]
}

print(json.dumps(body))
PYEOF2
)

HTTP_CODE=$(curl -s -o "$TMPOUT" -w "%{http_code}" \
  -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "$KIBANA_URL/api/saved_objects/search/threat-intel-ioc-matches?overwrite=true" \
  -d "$SAVED_SEARCH_BODY")

if [[ "$HTTP_CODE" =~ ^2 ]]; then
  echo "    Saved search created."
  echo "    Discover URL: $KIBANA_URL/app/discover#/view/threat-intel-ioc-matches"
else
  echo "    WARNING: Saved search creation returned HTTP $HTTP_CODE"
  jq '.' "$TMPOUT" 2>/dev/null || cat "$TMPOUT"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo " Deployment Complete"
echo "============================================"
echo " Index:      $INDEX_NAME"
echo " Dashboard:  $KIBANA_URL/app/dashboards#/view/threat-intel-findings-overview-v2"
echo " Discover:   $KIBANA_URL/app/discover#/view/threat-intel-ioc-matches"
echo ""
echo " Next steps:"
echo "   1. Seed data:  ./seed-threat-intel-data.sh"
echo "   2. Open dashboard and set time range to Last 30 days"
echo "   3. Click 'Active IOC Matches' saved search in Discover to investigate"
echo "============================================"
