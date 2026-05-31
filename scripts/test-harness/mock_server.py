#!/usr/bin/env python3
"""
Mock vendor API server for the Splunk-SOAR-translated workflows.

One process answers for every vendor URL the workflows call (Microsoft
Graph, CrowdStrike Falcon, ServiceNow, VirusTotal, Splunk REST, GreyNoise,
Recorded Future, Cisco Umbrella, Palo Alto Panorama, Zscaler ZIA, AWS,
GCP, ReversingLabs, etc.). Each handler returns realistic canned JSON
that satisfies the downstream `if`/`data.set` references in the workflow.

Usage:
    python3 mock_server.py [--port 8080] [--bind 0.0.0.0]

Then in your workflows, override every endpoint constant to point at this
server, e.g.:
    consts:
      graph_base: "http://localhost:8080/v1.0"
      crowdstrike_base_url: "http://localhost:8080"
      servicenow_endpoint: "http://localhost:8080/api/now/table"

To expose from your laptop to Elastic Cloud, use cloudflared or ngrok:
    cloudflared tunnel --url http://localhost:8080

No external dependencies — uses only Python stdlib.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


# Each entry: (compiled_regex, method_set_or_None, handler_fn)
# Handler fn signature: (request_handler, path, query, body_bytes) -> (status, json_dict)
ROUTES: list = []


def route(pattern: str, methods=None):
    rx = re.compile(pattern)
    def deco(fn):
        ROUTES.append((rx, set(methods) if methods else None, fn))
        return fn
    return deco


# ─── Microsoft Graph ──────────────────────────────────────────────────

@route(r"^/v1\.0/users/[^/]+$", methods={"GET", "PATCH"})
def graph_user(h, path, query, body):
    user_id = path.rsplit("/", 1)[-1]
    return 200, {
        "id": user_id,
        "userPrincipalName": f"{user_id}@example.com",
        "displayName": "Mock User",
        "accountEnabled": True,
        "createdDateTime": "2024-01-15T12:00:00Z",
    }


@route(r"^/v1\.0/users$", methods={"GET"})
def graph_list_users(h, path, query, body):
    return 200, {
        "value": [
            {"id": "user-aaa", "userPrincipalName": "alice@example.com", "createdDateTime": "2024-01-01T00:00:00Z", "accountEnabled": True},
            {"id": "user-bbb", "userPrincipalName": "bob@example.com",   "createdDateTime": "2024-01-02T00:00:00Z", "accountEnabled": True},
        ],
        "@odata.count": 2,
    }


@route(r"^/v1\.0/users/[^/]+/messages$", methods={"GET"})
def graph_messages(h, path, query, body):
    return 200, {
        "value": [
            {"id": f"msg-{uuid.uuid4().hex[:8]}", "subject": "Mock subject", "internetMessageId": "<mock@example.com>"}
        ]
    }


@route(r"^/v1\.0/users/[^/]+/messages/[^/]+(/move)?$", methods={"DELETE", "POST"})
def graph_message_action(h, path, query, body):
    return 200, {"id": path.rsplit("/", 1)[-1], "status": "ok"}


# ─── Microsoft Defender for Endpoint ─────────────────────────────────

@route(r"^/api/machines/[^/]+/isolate$", methods={"POST"})
def defender_isolate(h, path, query, body):
    machine_id = path.split("/")[-2]
    return 201, {
        "@odata.context": "$metadata#MachineActions/$entity",
        "id": f"action-{uuid.uuid4().hex[:8]}",
        "machineId": machine_id,
        "type": "Isolate",
        "status": "Pending",
    }


@route(r"^/api/machines/[^/]+/unisolate$", methods={"POST"})
def defender_unisolate(h, path, query, body):
    machine_id = path.split("/")[-2]
    return 201, {"id": f"action-{uuid.uuid4().hex[:8]}", "machineId": machine_id, "type": "Unisolate", "status": "Pending"}


@route(r"^/api/indicators$", methods={"POST"})
def defender_indicators(h, path, query, body):
    return 201, {"id": str(uuid.uuid4()), "indicatorValue": "mock", "action": "Block"}


# ─── CrowdStrike Falcon ──────────────────────────────────────────────

@route(r"^/oauth2/token$", methods={"POST"})
def falcon_token(h, path, query, body):
    return 200, {"access_token": "MOCK_FALCON_BEARER", "expires_in": 1799, "token_type": "bearer"}


@route(r"^/devices/queries/devices/v1$", methods={"GET"})
def falcon_query_devices(h, path, query, body):
    return 200, {
        "meta": {"query_time": 0.001, "pagination": {"offset": 0, "limit": 100, "total": 2}},
        "resources": ["aid-mock-aaaa", "aid-mock-bbbb"],
    }


@route(r"^/devices/entities/devices/v[12]$", methods={"GET"})
def falcon_device_details(h, path, query, body):
    return 200, {
        "meta": {"query_time": 0.001},
        "resources": [
            {"device_id": "aid-mock-aaaa", "hostname": "mock-host-01", "platform_name": "Windows",
             "external_ip": "203.0.113.5", "local_ip": "10.0.0.5", "status": "normal",
             "first_seen": "2024-01-01T00:00:00Z", "last_seen": "2024-06-01T00:00:00Z"},
        ],
    }


@route(r"^/devices/entities/devices-actions/v2$", methods={"POST"})
def falcon_device_action(h, path, query, body):
    action = (query.get("action_name", ["unknown"])[0]) if query else "unknown"
    return 202, {
        "meta": {"query_time": 0.005},
        "resources": [{"id": "aid-mock-aaaa", "code": 202, "path": f"/{action}"}],
    }


@route(r"^/real-time-response/entities/sessions/v1$", methods={"POST", "DELETE"})
def falcon_rtr_session(h, path, query, body):
    return 200, {"meta": {}, "resources": [{"session_id": f"sess-{uuid.uuid4().hex[:8]}"}]}


@route(r"^/real-time-response/entities/admin-command/v1$", methods={"POST"})
def falcon_rtr_command(h, path, query, body):
    return 201, {"meta": {}, "resources": [{"cloud_request_id": f"cmd-{uuid.uuid4().hex[:8]}", "queued_command_offline": False}]}


@route(r"^/iocs/entities/indicators/v1$", methods={"POST", "DELETE"})
def falcon_iocs(h, path, query, body):
    return 200, {"meta": {}, "resources": [{"id": f"ioc-{uuid.uuid4().hex[:8]}", "value": "mock"}]}


@route(r"^/processes/entities/processes/v1$", methods={"GET"})
def falcon_processes(h, path, query, body):
    return 200, {"meta": {}, "resources": [{"process_id": "pid-mock", "command_line": "mock.exe", "device_id": "aid-mock-aaaa"}]}


@route(r"^/falconx/entities/submissions/v1$", methods={"POST", "GET"})
def falcon_sandbox(h, path, query, body):
    return 200, {"meta": {}, "resources": [{"id": "sandbox-mock", "verdict": "no_specific_threat", "intel": {"malware_family": "None"}}]}


# ─── ServiceNow Table API ─────────────────────────────────────────────

@route(r"^/api/now/table/[^/]+$", methods={"GET", "POST"})
def snow_table(h, path, query, body):
    if h.command == "POST":
        return 201, {"result": {
            "sys_id": uuid.uuid4().hex,
            "number": f"INC{int(time.time()) % 10000000:07d}",
            "short_description": "Mock incident",
            "state": "1",
            "urgency": "2",
        }}
    return 200, {"result": [
        {"sys_id": uuid.uuid4().hex, "number": "INC0010001", "short_description": "Existing mock incident", "state": "2"}
    ]}


@route(r"^/api/now/table/[^/]+/[^/]+$", methods={"GET", "PATCH", "PUT"})
def snow_record(h, path, query, body):
    sys_id = path.rsplit("/", 1)[-1]
    return 200, {"result": {"sys_id": sys_id, "number": "INC0010001", "state": "2", "short_description": "Updated"}}


# ─── Jira Cloud REST v3 ───────────────────────────────────────────────

@route(r"^/rest/api/3/issue$", methods={"POST"})
def jira_issue_create(h, path, query, body):
    return 201, {"id": "10001", "key": "DEMO-1", "self": "http://localhost:8080/rest/api/3/issue/10001"}


@route(r"^/rest/api/3/issue/[^/]+$", methods={"GET", "PUT"})
def jira_issue(h, path, query, body):
    key = path.rsplit("/", 1)[-1]
    return 200, {"id": "10001", "key": key, "fields": {"summary": "Mock issue", "status": {"name": "Open"}}}


@route(r"^/rest/api/3/search(/jql)?$", methods={"POST", "GET"})
def jira_search(h, path, query, body):
    return 200, {"issues": [{"id": "10001", "key": "DEMO-1", "fields": {"summary": "Mock issue"}}], "total": 1}


# ─── Splunk REST ──────────────────────────────────────────────────────

@route(r"^/services/search/jobs(/export)?$", methods={"POST"})
def splunk_search(h, path, query, body):
    return 200, {
        "preview": False,
        "init_offset": 0,
        "results": [
            {"_time": "2026-01-01T00:00:00Z", "host": "mock-host-01", "user": "alice", "action": "login"},
            {"_time": "2026-01-01T00:01:00Z", "host": "mock-host-01", "user": "alice", "action": "logoff"},
        ],
    }


@route(r"^/services/notable_update$", methods={"POST"})
def splunk_notable_update(h, path, query, body):
    return 200, {"success": True, "message": "Notable updated", "ruleUIDs": []}


# ─── VirusTotal v3 ────────────────────────────────────────────────────

@route(r"^/api/v3/files/[^/]+$", methods={"GET"})
def vt_file(h, path, query, body):
    h_ = path.rsplit("/", 1)[-1]
    return 200, {"data": {"id": h_, "type": "file", "attributes": {
        "last_analysis_stats": {"harmless": 60, "malicious": 5, "suspicious": 1, "undetected": 4, "timeout": 0},
        "reputation": -25, "meaningful_name": "mock.exe", "size": 12345,
        "first_submission_date": 1700000000, "last_submission_date": 1750000000,
        "popular_threat_classification": {"suggested_threat_label": "trojan.mock/generic"},
    }}}


@route(r"^/api/v3/urls$", methods={"POST"})
def vt_url_submit(h, path, query, body):
    return 200, {"data": {"id": "u-" + uuid.uuid4().hex[:16], "type": "analysis"}}


@route(r"^/api/v3/analyses/[^/]+$", methods={"GET"})
def vt_analysis(h, path, query, body):
    return 200, {"data": {"id": path.rsplit("/", 1)[-1], "type": "analysis", "attributes": {
        "status": "completed",
        "stats": {"harmless": 70, "malicious": 3, "suspicious": 0, "undetected": 5, "timeout": 0},
    }}}


@route(r"^/api/v3/ip_addresses/[^/]+$", methods={"GET"})
def vt_ip(h, path, query, body):
    ip = path.rsplit("/", 1)[-1]
    return 200, {"data": {"id": ip, "type": "ip_address", "attributes": {
        "last_analysis_stats": {"harmless": 80, "malicious": 0, "suspicious": 0, "undetected": 4, "timeout": 0},
        "country": "US", "as_owner": "Mock ASN", "reputation": 0,
    }}}


@route(r"^/api/v3/domains/[^/]+$", methods={"GET"})
def vt_domain(h, path, query, body):
    d = path.rsplit("/", 1)[-1]
    return 200, {"data": {"id": d, "type": "domain", "attributes": {
        "last_analysis_stats": {"harmless": 75, "malicious": 1, "suspicious": 0, "undetected": 5, "timeout": 0},
        "reputation": -5, "categories": {"BitDefender": "uncategorized"},
    }}}


# ─── URLScan.io ───────────────────────────────────────────────────────

@route(r"^/api/v1/scan/?$", methods={"POST"})
def urlscan_submit(h, path, query, body):
    sid = str(uuid.uuid4())
    return 200, {"uuid": sid, "result": f"http://localhost:8080/api/v1/result/{sid}/", "api": f"http://localhost:8080/api/v1/result/{sid}/", "visibility": "public"}


@route(r"^/api/v1/result/[^/]+/?$", methods={"GET"})
def urlscan_result(h, path, query, body):
    return 200, {
        "task": {"uuid": path.split("/")[-2], "url": "https://example.com", "reportURL": "https://urlscan.io/result/mock"},
        "verdicts": {
            "overall": {"score": 0, "malicious": False, "categories": []},
            "urlscan": {"score": 0, "malicious": False},
            "community": {"score": 0, "votes": 0, "malicious": False},
            "engines": {"score": 0, "malicious": []},
        },
        "page": {"domain": "example.com", "ip": "203.0.113.5", "country": "US"},
    }


# ─── PhishTank ────────────────────────────────────────────────────────

@route(r"^/checkurl/?$", methods={"POST"})
def phishtank_check(h, path, query, body):
    return 200, {"meta": {"timestamp": int(time.time())}, "results": {
        "url": "https://example.com/login",
        "in_database": False, "verified": False, "valid": False,
        "phish_detail_page": "",
    }}


# ─── GreyNoise v3 ─────────────────────────────────────────────────────

@route(r"^/v3/community/[^/]+$", methods={"GET"})
def gn_community(h, path, query, body):
    ip = path.rsplit("/", 1)[-1]
    return 200, {"ip": ip, "noise": False, "riot": False, "classification": "benign", "name": "Mock Scanner", "last_seen": "2026-05-01"}


@route(r"^/v3/noise/quick/[^/]+$", methods={"GET"})
def gn_quick(h, path, query, body):
    ip = path.rsplit("/", 1)[-1]
    return 200, {"ip": ip, "noise": False, "code": "0x00", "code_message": "IP has never been observed scanning the internet"}


@route(r"^/v3/noise/context/[^/]+$", methods={"GET"})
def gn_context(h, path, query, body):
    ip = path.rsplit("/", 1)[-1]
    return 200, {
        "ip": ip, "first_seen": "2024-01-01", "last_seen": "2026-05-01",
        "actor": "Mock Actor", "classification": "benign", "tags": ["scanner"],
        "metadata": {"country": "US", "organization": "Mock"}, "raw_data": {},
    }


@route(r"^/v3/experimental/gnql$", methods={"GET", "POST"})
def gn_gnql(h, path, query, body):
    return 200, {"count": 0, "data": [], "message": "ok", "query": "mock"}


# ─── Recorded Future v2 ───────────────────────────────────────────────

@route(r"^/v2/(ip|domain|hash|url)/[^/]+$", methods={"GET"})
def rf_entity(h, path, query, body):
    return 200, {"data": {
        "entity": {"id": "mock-id", "name": path.rsplit("/", 1)[-1], "type": path.split("/")[2]},
        "risk": {"score": 25, "level": "Suspicious", "evidenceDetails": [], "criticality": 2, "criticalityLabel": "Suspicious"},
        "timestamps": {"firstSeen": "2024-01-01T00:00:00Z", "lastSeen": "2026-05-01T00:00:00Z"},
        "intelCard": "https://app.recordedfuture.com/portal/intelligence-card/mock",
    }}


# ─── Cisco Umbrella Enforcement ───────────────────────────────────────

@route(r"^/1\.0/events/?$", methods={"POST"})
def umbrella_events(h, path, query, body):
    return 202, {"id": uuid.uuid4().hex, "status": "accepted"}


@route(r"^/1\.0/domains/?$", methods={"GET", "POST"})
def umbrella_domains(h, path, query, body):
    return 200, [{"id": uuid.uuid4().hex, "name": "evil.example.com"}]


# ─── Palo Alto Panorama XML API ───────────────────────────────────────

@route(r"^/api/?$", methods={"GET", "POST"})
def panorama_api(h, path, query, body):
    # Panorama returns XML; emit a minimal "success" envelope as a JSON wrapper
    # since the workflows often parse status from the response body
    return 200, {"response": {"status": "success", "result": {"msg": "command succeeded"}}}


# ─── Zscaler ZIA ──────────────────────────────────────────────────────

@route(r"^/api/v1/authenticatedSession$", methods={"POST", "DELETE"})
def zia_session(h, path, query, body):
    if h.command == "POST":
        h._extra_set_cookie = "JSESSIONID=mock-jsessionid-abc; Path=/"
        return 200, {"authType": "ANY", "obfuscateApiKey": False}
    return 200, {"status": "ok"}


@route(r"^/api/v1/urlCategories(/[^/]+)?(/lookup)?$", methods={"GET", "PUT", "POST"})
def zia_url_categories(h, path, query, body):
    if path.endswith("/lookup"):
        return 200, [{"url": "https://example.com", "urlClassifications": ["NEWS"], "urlClassificationsWithSecurityAlert": []}]
    return 200, {"id": "USER_DEFINED_1", "configuredName": "Blocked", "urls": ["evil.example.com"], "customCategory": True}


@route(r"^/api/v1/status/activate$", methods={"POST"})
def zia_activate(h, path, query, body):
    return 200, {"status": "ACTIVE"}


# ─── AWS (SigV4 stubs) ────────────────────────────────────────────────

@route(r"^/(\?Action=.*)?$", methods={"GET", "POST"})
def aws_action(h, path, query, body):
    action = (query.get("Action", ["Unknown"])[0]) if query else "Unknown"
    return 200, {"ResponseMetadata": {"RequestId": uuid.uuid4().hex}, "Action": action, "Result": "mock"}


# ─── GCP Compute ──────────────────────────────────────────────────────

@route(r"^/compute/v1/projects/[^/]+/zones/[^/]+/instances/[^/]+/stop$", methods={"POST"})
def gcp_stop(h, path, query, body):
    return 200, {"id": uuid.uuid4().hex, "name": "stop-operation-mock", "status": "RUNNING", "operationType": "stop"}


@route(r"^/compute/v1/projects/[^/]+/zones/[^/]+/instances/[^/]+$", methods={"GET", "DELETE", "PATCH"})
def gcp_instance(h, path, query, body):
    return 200, {"id": "1234567890", "name": path.rsplit("/", 1)[-1], "status": "RUNNING", "machineType": "n1-standard-1"}


@route(r"^/iam/v1/projects/[^/]+/serviceAccounts(/[^/]+)?(/keys)?$", methods={"GET", "POST", "DELETE"})
def gcp_iam_sa(h, path, query, body):
    return 200, {"accounts": [], "keys": []}


# ─── ReversingLabs ────────────────────────────────────────────────────

@route(r"^/api/databrowser/malware_presence/query/sha256/[^/]+$", methods={"GET"})
def rl_malware_presence(h, path, query, body):
    return 200, {"rl": {"malware_presence": {
        "status": "MALICIOUS", "threat_name": "Trojan.Mock", "threat_level": 5,
        "trust_factor": 5, "first_seen": "2024-01-01", "last_seen": "2026-05-01",
        "sha256": path.rsplit("/", 1)[-1], "sha1": "0"*40, "md5": "0"*32,
    }}}


@route(r"^/api/networking/url/v1/report/query/json$", methods={"POST"})
def rl_url_ti(h, path, query, body):
    return 200, {"rl": {"classification": "malicious", "categories": ["phishing"], "first_seen": "2024-01-01", "third_party_reputations": []}}


@route(r"^/api/uploads/v2/upload-file$", methods={"POST"})
def rl_a1000_upload(h, path, query, body):
    return 200, {"detail": {"id": uuid.uuid4().hex, "sha1": "0"*40, "sha256": "0"*64}}


@route(r"^/api/samples/v2/[^/]+/?$", methods={"GET"})
def rl_a1000_sample(h, path, query, body):
    return 200, {"results": [{"sha1": path.split("/")[-2], "classification": "malicious", "threat_name": "Trojan.Mock"}]}


@route(r"^/api/tiscale/v1/upload$", methods={"POST"})
def rl_tiscale(h, path, query, body):
    return 200, {"task_id": uuid.uuid4().hex, "tc_report": {"classification": {"classification": 3, "factor": 5}}}


# ─── MaxMind GeoIP ────────────────────────────────────────────────────

@route(r"^/geoip/v2\.1/city/[^/]+$", methods={"GET"})
def maxmind(h, path, query, body):
    return 200, {"city": {"names": {"en": "Mockville"}}, "country": {"iso_code": "US", "names": {"en": "United States"}}, "location": {"latitude": 0, "longitude": 0}}


# ─── crt.sh ───────────────────────────────────────────────────────────

@route(r"^/$", methods={"GET"})
def crtsh(h, path, query, body):
    # crt.sh returns a JSON array
    return 200, [{"issuer_ca_id": 1, "name_value": "example.com", "not_before": "2026-01-01", "not_after": "2026-12-31"}]


# ─── Carbon Black ─────────────────────────────────────────────────────

@route(r"^/api/v1/banning/blacklist$", methods={"POST"})
def cb_blacklist(h, path, query, body):
    return 200, {"id": uuid.uuid4().hex, "md5hash": "0"*32, "text": "Mock ban"}


@route(r"^/api/v1/process(/[^/]+)?(/terminate|/event)?$", methods={"GET", "POST"})
def cb_process(h, path, query, body):
    return 200, {"results": [{"id": "proc-mock", "sensor_id": 1, "process_name": "mock.exe", "cmdline": "mock.exe -x"}]}


@route(r"^/api/v1/sensor(/[^/]+)?$", methods={"GET", "PUT"})
def cb_sensor(h, path, query, body):
    return 200, {"id": 1, "computer_name": "mock-host-01", "network_isolation_enabled": True, "group_id": 1}


@route(r"^/api/investigate/v2/orgs/[^/]+/processes/search_jobs$", methods={"POST"})
def cb_cloud_search(h, path, query, body):
    return 200, {"job_id": uuid.uuid4().hex}


@route(r"^/orgs/[^/]+/device_actions$", methods={"POST"})
def cb_cloud_actions(h, path, query, body):
    return 200, {"id": uuid.uuid4().hex, "type": "QUARANTINE", "device_id": [1], "status": "PENDING"}


# ─── Vectra Detect ────────────────────────────────────────────────────

@route(r"^/api/v2\.5/detections$", methods={"GET"})
def vectra_detections(h, path, query, body):
    return 200, {"count": 1, "results": [{"id": 1001, "category": "COMMAND & CONTROL", "src_ip": "10.0.0.5", "state": "active", "threat_score": 80}]}


# ─── ExtraHop ─────────────────────────────────────────────────────────

@route(r"^/activitymaps/query$", methods={"POST"})
def extrahop_amap(h, path, query, body):
    return 200, {"vertices": [], "edges": []}


@route(r"^/devices(/[^/]+)?(/tags)?$", methods={"GET", "POST", "PATCH"})
def extrahop_devices(h, path, query, body):
    return 200, [{"id": 1, "display_name": "mock-host-01", "ipaddr4": "10.0.0.5", "tags": []}]


# ─── Cisco Talos (no public API) ─────────────────────────────────────

@route(r"^/talos(/.*)?$", methods={"GET", "POST"})
def talos_stub(h, path, query, body):
    return 200, {"status": "ok", "note": "Cisco Talos has no public reputation API; this is a SecureX-broker mock."}


# ─── Mission Control / SOAR workbook surrogate ────────────────────────

@route(r"^/(workbook|mission-control|tasks)(/.*)?$", methods={"GET", "POST", "PUT"})
def workbook(h, path, query, body):
    return 200, {"task_id": uuid.uuid4().hex, "status": "ok"}


# ─── AD LDAP proxy stub ───────────────────────────────────────────────

@route(r"^/(disable-user|enable-user|reset-password|unlock-user|run-query|get-user)$", methods={"POST"})
def ldap_proxy(h, path, query, body):
    return 200, {"status": "success", "message": f"{path.lstrip('/')} ok", "user_dn": "CN=Mock User,DC=example,DC=com"}


# ─── Censys / Nessus / threat intel one-offs ──────────────────────────

@route(r"^/v2/hosts/[^/]+$", methods={"GET"})
def censys_host(h, path, query, body):
    return 200, {"result": {"ip": path.rsplit("/", 1)[-1], "services": [{"port": 443, "service_name": "HTTPS"}], "location": {"country": "US"}}}


@route(r"^/scans(/[^/]+)?(/launch)?$", methods={"GET", "POST"})
def nessus_scans(h, path, query, body):
    return 200, {"scans": [{"id": 1, "name": "Mock scan", "status": "completed"}], "scan_uuid": uuid.uuid4().hex}


# ─── Sub-workflow self-call (Kibana /api/workflows/{id}/run) ──────────

@route(r"^/api/workflows/[^/]+/run$", methods={"POST"})
@route(r"^/api/workflows/[^/]+/_execute$", methods={"POST"})
def child_workflow(h, path, query, body):
    return 200, {"workflowRunId": uuid.uuid4().hex, "status": "started"}


# ─── Catchall: 200 OK with generic JSON ──────────────────────────────

def catchall(h, path, query, body):
    return 200, {"status": "ok", "mock": True, "path": path, "method": h.command}


# ─── HTTP handler ────────────────────────────────────────────────────

class MockHandler(BaseHTTPRequestHandler):
    server_version = "MockVendorAPI/1.0"

    def _dispatch(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        # Read body
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        for rx, methods, fn in ROUTES:
            if methods and self.command not in methods:
                continue
            if rx.match(path):
                status, payload = fn(self, path, query, body)
                self._send(status, payload)
                return

        status, payload = catchall(self, path, query, body)
        self._send(status, payload)

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        extra = getattr(self, "_extra_set_cookie", None)
        if extra:
            self.send_header("Set-Cookie", extra)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):     self._dispatch()
    def do_POST(self):    self._dispatch()
    def do_PUT(self):     self._dispatch()
    def do_PATCH(self):   self._dispatch()
    def do_DELETE(self):  self._dispatch()

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{self.command}] {self.path}  →  {fmt % args}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), MockHandler)
    print(f"Mock vendor API server listening on http://{args.bind}:{args.port}", file=sys.stderr)
    print(f"Routes registered: {len(ROUTES)} specific + 1 catchall", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.", file=sys.stderr)


if __name__ == "__main__":
    main()
