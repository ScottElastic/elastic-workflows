#!/usr/bin/env bash
# Seed threat-intel-findings index with the 8 findings from the 2026-04-07 run.
# This data was produced by the AI agent but couldn't be indexed (read-only tools).
set -euo pipefail

# Required: ES_URL must be set.
#   export ES_URL="https://YOUR-DEPLOYMENT.es.REGION.PROVIDER.elastic-cloud.com"
# Auth — pick ONE:
#   1. ES_API_KEY (recommended): export ES_API_KEY="<base64 id:api_key>"
#   2. KIBANA_USERNAME / KIBANA_PASSWORD (basic auth fallback)
: "${ES_URL:?ES_URL is required}"
if [[ -n "${ES_API_KEY:-}" ]]; then
  AUTH="Authorization: ApiKey $ES_API_KEY"
else
  : "${KIBANA_USERNAME:?Set ES_API_KEY, or KIBANA_USERNAME and KIBANA_PASSWORD}"
  : "${KIBANA_PASSWORD:?Set ES_API_KEY, or KIBANA_USERNAME and KIBANA_PASSWORD}"
  AUTH="Authorization: Basic $(printf '%s:%s' "$KIBANA_USERNAME" "$KIBANA_PASSWORD" | base64)"
fi

echo "==> Seeding threat-intel-findings with 8 documents..."

curl -s -S -X POST \
  -H "$AUTH" \
  -H "Content-Type: application/x-ndjson" \
  "$ES_URL/threat-intel-findings/_bulk?refresh=true" \
  --data-binary '{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"Axios Supply Chain Compromise","type":"supply_chain","severity":"critical","description":"DPRK-attributed compromise of the axios npm package delivering a cross-platform RAT via malicious postinstall hook in plain-crypto-js dependency."},"exposure":{"level":"high","score":75,"notes":"No IOC matches found. Developer workstations and CI/CD pipelines lack dedicated monitoring."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["crowdstrike.fdr","crowdstrike.falcon","panw.panos","iis.access"],"mitre":{"technique_ids":["T1195.001","T1059.007","T1059.001","T1059.002","T1059.006","T1547.001","T1036","T1071.001","T1571","T1132.001","T1105"],"tactic_names":["initial-access","execution","persistence","defense-evasion","discovery","command-and-control"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"VoidLink Rootkit Framework","type":"rootkit","severity":"critical","description":"Sophisticated hybrid LKM+eBPF Linux rootkit with ICMP covert C2, delayed hook installation, and anti-debugging. AI-assisted development by Chinese-speaking actor."},"exposure":{"level":"blind_spot","score":98,"notes":"Zero Linux endpoint telemetry. VoidLink and all Linux rootkit variants completely invisible."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["panw.panos"],"mitre":{"technique_ids":["T1014","T1547.006","T1059.004","T1036.005","T1070.004","T1095"],"tactic_names":["defense-evasion","persistence","execution","command-and-control"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"BRUSHWORM and BRUSHLOGGER","type":"backdoor_keylogger","severity":"high","description":"Custom backdoor targeting South Asian financial institution with USB worm propagation, air-gap bridging, and DLL side-loaded keylogger."},"exposure":{"level":"medium","score":55,"notes":"No IOC matches found. CrowdStrike provides coverage for USB spreading and scheduled task persistence."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["crowdstrike.fdr","crowdstrike.falcon","panw.panos"],"mitre":{"technique_ids":["T1053.005","T1574.002","T1056.001","T1091","T1025","T1119","T1074.001","T1105","T1036.005","T1497.001"],"tactic_names":["execution","persistence","defense-evasion","credential-access","discovery","lateral-movement","collection","exfiltration","command-and-control"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"REF1695 Fake Installers to Monero","type":"cryptominer_rat","severity":"medium","description":"Financially motivated operation deploying PureRAT, PureMiner, CNB Bot, SilentCryptoMiner, and custom XMRig loaders through fake installer ISOs."},"exposure":{"level":"medium","score":50,"notes":"No IOC matches found. CrowdStrike would likely detect Themida-packed loaders."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["crowdstrike.fdr","crowdstrike.falcon","panw.panos"],"mitre":{"technique_ids":["T1204.002","T1059.001","T1053.005","T1055","T1497.001","T1496"],"tactic_names":["execution","persistence","defense-evasion","privilege-escalation","impact"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"SILENTCONNECT ScreenConnect Loader","type":"loader_rmm_abuse","severity":"high","description":"Multi-stage loader using VBScript, in-memory C# compilation, PEB masquerading, and UAC bypass to silently deploy ScreenConnect RMM tool."},"exposure":{"level":"medium","score":55,"notes":"No IOC matches found. CrowdStrike provides coverage for PowerShell and UAC bypass stages."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["crowdstrike.fdr","crowdstrike.falcon","panw.panos"],"mitre":{"technique_ids":["T1059.001","T1562.001","T1548.002","T1219.002","T1105","T1027"],"tactic_names":["execution","defense-evasion","privilege-escalation","command-and-control"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"TeamPCP Container Attack","type":"container_cryptojacking_ransomware","severity":"high","description":"Cloud-native ransomware operation targeting Kubernetes via container compromise, service account token abuse, privileged DaemonSet deployment, and cryptominer installation."},"exposure":{"level":"blind_spot","score":96,"notes":"Zero container runtime monitoring and no Kubernetes audit log collection. All attack stages completely invisible."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["aws.cloudtrail"],"mitre":{"technique_ids":["T1610","T1053.007","T1552.001","T1078.004","T1496"],"tactic_names":["execution","persistence","credential-access","privilege-escalation","impact"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"Linux Rootkit Ecosystem","type":"rootkit","severity":"high","description":"Comprehensive Linux rootkit threat spanning userland SO hijacking, LKM syscall hooking, ftrace abuse, eBPF programs, and io_uring evasion."},"exposure":{"level":"blind_spot","score":97,"notes":"Zero Linux endpoint visibility. All rootkit loading, persistence, and defense evasion techniques completely undetectable."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":[],"mitre":{"technique_ids":["T1014","T1547.006","T1574.006","T1059.004","T1070.002","T1070.004","T1036.005"],"tactic_names":["defense-evasion","persistence","execution","privilege-escalation"]}}
{"index":{}}
{"@timestamp":"2026-04-07T14:02:00.000Z","feed":{"name":"elastic-security-labs","url":"https://www.elastic.co/security-labs/rss/feed.xml","run_timestamp":"2026-04-07T14:02:00.000Z"},"event":{"kind":"enrichment","category":"threat","type":"indicator"},"threat":{"name":"DWM Use-After-Free Privilege Escalation","type":"local_privilege_escalation","severity":"high","description":"Use-After-Free in Windows DWM dwmcore.dll, exploitable from low-privileged user to SYSTEM. Patched January 2026."},"exposure":{"level":"medium","score":45,"notes":"Patched vulnerability requiring local access. Risk depends on Windows patch compliance."},"ioc":{"matched":false,"match_count":0},"affected_hosts":[],"data_sources":["crowdstrike.fdr","crowdstrike.falcon","system.security"],"mitre":{"technique_ids":["T1068"],"tactic_names":["privilege-escalation"]}}
' | jq .

echo ""
echo "==> Verifying..."
curl -s -S \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  "$ES_URL/threat-intel-findings/_count" | jq .

echo ""
echo "Done. Data seeded."
