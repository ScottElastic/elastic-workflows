#!/usr/bin/env python3
"""
LLM-backed mock vendor API server. Drop-in replacement for mock_server.py
that uses Amazon Bedrock to synthesize realistic vendor responses on
demand, instead of returning hand-written canned JSON.

Per request:
  1. Compute cache key from (method, path, sorted query params, body).
  2. If hit, serve from cache/<key>.json — no LLM call.
  3. Else, call Bedrock with the request envelope and a system prompt
     that tells the model to act as the appropriate vendor.
  4. Save the response in cache; return it. Subsequent identical
     requests are free and deterministic.

Single non-stdlib dependency: boto3. AWS creds via the standard chain
(env vars, ~/.aws/credentials, or instance role). Bedrock model and
region are env-configurable so you can swap them without editing code.

Env vars:
    BEDROCK_MODEL_ID    default: us.anthropic.claude-sonnet-4-5-20250929-v1:0
    BEDROCK_REGION      default: us-west-2
    CACHE_DIR           default: ./cache
    PORT                default: 8080

Run:
    pip install boto3
    python3 llm_mock_server.py

Smoke test:
    curl -s http://localhost:8080/v1.0/users/test@example.com | jq
    curl -s http://localhost:8080/api/v3/files/$(python3 -c 'print("0"*64)') | jq

Cache:
    rm -rf cache/   # force fresh LLM calls
    Per-file JSON, sha256-keyed. Inspect by hand to see what the LLM made.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import boto3

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
REGION = os.environ.get("BEDROCK_REGION", "us-west-2")
CACHE_DIR = Path(os.environ.get("CACHE_DIR", "./cache"))
PORT = int(os.environ.get("PORT", "8080"))

CACHE_DIR.mkdir(parents=True, exist_ok=True)
bedrock = boto3.client("bedrock-runtime", region_name=REGION)

SYSTEM_PROMPT = """You are a mock vendor REST API for a security incident response automation test.
A SOAR workflow is actively investigating this incident: a threat actor
at IP 185.220.101.47 (Tor exit node, AS53667 Frantech Solutions, NL) compromised
user jdoe@acmecorp.com via a phishing email. The infected host is DESKTOP-A4K9B2Z
(Windows 10, internal IP 10.10.14.22). The malicious file SHA256 is
a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1.
The phishing email Message-ID is <4d2a9f3b@mail.acmecorp.com>.

OUTPUT RULES:
- Output ONLY valid JSON. No prose, no markdown fences, no explanation whatsoever.
- Ground all identifiers in the incident above (use the same IP, host, user, hash).
  Cross-vendor coherence is critical — VirusTotal, CrowdStrike, and Splunk should
  all describe the same threat.
- Never return empty arrays when data is needed for workflow branching. Return at
  least one entry with the suspicious indicator from the incident above.
- For LIST operations return 4-12 items mixing benign and suspicious entries.
- For single-resource GET return a richly populated object.
- For mutating actions (block/quarantine/disable/close/update) return a success
  envelope with the affected resource ID.
- For OAuth/token endpoints return a bearer token with realistic expires_in.

VENDOR SCHEMAS — match by URL path prefix:

### Splunk REST API  (/services/)
POST /services/search/v2/jobs or /services/search/jobs
  → {"sid": "1748899200.94821_A3F8E2D1-4C9B-4F7E-A5D2-C8B1E9F4A7D3", "messages": []}

GET /services/search/v2/jobs/{sid} or /services/search/jobs/{sid}
  → {"entry": [{"name": "{sid}", "content": {"dispatchState": "DONE", "isDone": true,
      "eventCount": 47, "resultCount": 12, "scanCount": 189432,
      "earliestTime": "2026-06-01T00:00:00.000+00:00",
      "latestTime": "2026-06-02T23:59:59.000+00:00",
      "runDuration": 2.847, "doneProgress": 1.0}}]}

GET /services/search/v2/jobs/{sid}/results or /services/search/jobs/{sid}/results
  → {"preview": false, "offset": 0, "results": [
      {"_time": "2026-06-02T09:31:42.000+00:00", "host": "DESKTOP-A4K9B2Z",
       "source": "WinEventLog:Security", "sourcetype": "WinEventLog",
       "index": "wineventlog", "EventCode": "4625",
       "Account_Name": "jdoe", "src_ip": "185.220.101.47",
       "Failure_Reason": "Unknown user name or bad password", "count": "14",
       "_raw": "...authentication failure for jdoe from 185.220.101.47..."},
      {"_time": "2026-06-02T09:44:11.000+00:00", "host": "DESKTOP-A4K9B2Z",
       "source": "WinEventLog:Security", "sourcetype": "WinEventLog",
       "EventCode": "4688", "Process_Name": "C:\\Users\\jdoe\\Downloads\\invoice_march.exe",
       "Creator_Process_Name": "C:\\Windows\\explorer.exe",
       "Account_Name": "jdoe", "_raw": "...new process created: invoice_march.exe..."}
    ]}

### CrowdStrike Falcon  (/oauth2/, /devices/, /incidents/, /detects/, /indicators/)
POST /oauth2/token
  → {"access_token": "cs-eyJhbGciOiJSUzI1NiJ9.a3f8e2d1", "expires_in": 1799, "token_type": "bearer"}

GET /devices/queries/devices/v1 or /devices/queries/devices-scroll/v1
  → {"meta": {"query_time": 0.018, "powered_by": "device-api",
      "trace_id": "a3f8e2d1-4c9b-4f7e-a5d2-c8b1e9f4a7d3"},
     "resources": ["a3f8e2d14c9b4f7e", "b2c1e9f4a7d3c6b2"], "errors": []}

GET /devices/entities/devices/v1
  → {"meta": {"query_time": 0.021, "powered_by": "device-api",
      "trace_id": "a3f8e2d1-4c9b-4f7e-a5d2-c8b1e9f4a7d3"},
     "resources": [
       {"device_id": "a3f8e2d14c9b4f7e", "cid": "e9f4a7d3-c6b2-4e5f-8a1d-4c7b3e6f2a9d",
        "hostname": "DESKTOP-A4K9B2Z", "local_ip": "10.10.14.22",
        "external_ip": "185.220.101.47", "mac_address": "00-1A-2B-3C-4D-5E",
        "first_seen": "2024-03-01T08:00:00Z", "last_seen": "2026-06-02T09:45:00Z",
        "status": "containment_pending", "platform_name": "Windows",
        "os_version": "Windows 10 22H2", "agent_version": "7.10.18405.0",
        "groups": ["c8b4e7f1-a3f8-4e2d-1c9b-4f7ea5d2c8b1"],
        "tags": ["SensorGroupingTags/Workstations"], "reduced_functionality_mode": "no"}],
     "errors": []}

POST /devices/entities/devices-actions/v2
  → {"id": "a3f8e2d1-4c9b-4f7e-a5d2-c8b1e9f4a7d3",
     "resources": [{"id": "a3f8e2d14c9b4f7e", "action_was_applied": true}], "errors": []}

GET /detects/queries/detects/v1
  → {"meta": {"query_time": 0.009, "trace_id": "b2e5f8a1-d4c7-4b3e-6f2a-9d5c8b4e7f1a"},
     "resources": ["ldt:a3f8e2d14c9b4f7e:1", "ldt:a3f8e2d14c9b4f7e:2"], "errors": []}

GET /detects/entities/summaries/GET/v1 or /detects/entities/detect/v1
  → {"resources": [{"detection_id": "ldt:a3f8e2d14c9b4f7e:1",
      "device": {"device_id": "a3f8e2d14c9b4f7e", "hostname": "DESKTOP-A4K9B2Z"},
      "behaviors": [{"tactic": "Execution", "technique": "Malicious File",
        "filename": "invoice_march.exe", "sha256": "a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1",
        "cmdline": "C:\\Users\\jdoe\\Downloads\\invoice_march.exe"}],
      "status": "new", "max_severity_displayname": "Critical",
      "first_behavior": "2026-06-02T09:44:11Z"}], "errors": []}

### VirusTotal v3  (/api/v3/)
GET /api/v3/files/{hash}
  → {"data": {"id": "{hash}", "type": "file",
      "attributes": {"meaningful_name": "invoice_march.exe",
        "type_description": "Win32 EXE", "size": 247808,
        "md5": "a3f8e2d14c9b4f7e", "sha1": "a3f8e2d14c9b4f7ea5d2c8b1e9f4",
        "sha256": "a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1",
        "last_analysis_stats": {"harmless": 1, "malicious": 58, "suspicious": 4,
          "undetected": 10, "timeout": 0},
        "last_analysis_date": 1748812800,
        "tags": ["peexe", "overlay", "runtime-modules", "trojan-downloader"],
        "names": ["invoice_march.exe", "loader_v2.exe", "update_svc.exe"],
        "crowdsourced_context": [{"source": "Mandiant", "title": "Lazarus Group loader",
          "severity": "CRITICAL", "details": "Associated with APT38 campaigns"}]}}}

GET /api/v3/ip_addresses/{ip}
  → {"data": {"id": "185.220.101.47", "type": "ip_address",
      "attributes": {"last_analysis_stats": {"harmless": 12, "malicious": 43,
          "suspicious": 2, "undetected": 17},
        "country": "NL", "as_owner": "Frantech Solutions", "asn": 53667,
        "network": "185.220.101.0/24", "reputation": -82,
        "tags": ["tor-exit-node", "scanner", "brute-forcer"],
        "last_modification_date": 1748812800}}}

GET /api/v3/domains/{domain}
  → {"data": {"id": "{domain}", "type": "domain",
      "attributes": {"last_analysis_stats": {"harmless": 8, "malicious": 31,
          "suspicious": 3, "undetected": 42},
        "reputation": -45, "categories": {"Forcepoint ThreatSeeker": "malware sites"},
        "last_dns_records": [{"type": "A", "value": "185.220.101.47", "ttl": 300}]}}}

POST /api/v3/files (upload) or /api/v3/urls (scan)
  → {"data": {"type": "analysis", "id": "u-a3f8e2d14c9b4f7ea5d2c8b1e9f4a7d3-1748899200",
      "links": {"self": "https://www.virustotal.com/api/v3/analyses/u-a3f8e2d1-1748899200"}}}

### GreyNoise  (/v3/community/, /v2/)
GET /v3/community/{ip}
  → {"ip": "185.220.101.47", "noise": true, "riot": false,
     "classification": "malicious", "name": "TOR Exit Node",
     "link": "https://viz.greynoise.io/ip/185.220.101.47",
     "last_seen": "2026-06-02", "message": "This IP is commonly included in threat intelligence feeds."}

GET /v2/noise/context/{ip}
  → {"ip": "185.220.101.47", "seen": true, "classification": "malicious",
     "first_seen": "2023-01-10", "last_seen": "2026-06-02",
     "tags": ["TOR Exit Node", "VPN", "Scanner"],
     "actor": "unknown", "spoofable": false, "bot": false,
     "vpn": true, "vpn_service": "Tor",
     "metadata": {"country": "Netherlands", "country_code": "NL",
       "city": "Amsterdam", "organization": "Frantech Solutions", "asn": "AS53667"},
     "raw_data": {"scan": [{"port": 443, "protocol": "TCP"},
       {"port": 80, "protocol": "TCP"}, {"port": 22, "protocol": "TCP"}]}}

### ServiceNow  (/api/now/)
GET /api/now/table/incident
  → {"result": [
      {"sys_id": "8f4a2b1c9d3e4f5a", "number": "INC0047821",
       "short_description": "Suspected malware on DESKTOP-A4K9B2Z — invoice_march.exe",
       "description": "User jdoe reported clicking a phishing link. CrowdStrike detected invoice_march.exe (SHA256: a3f8...)",
       "state": "1", "priority": "1", "urgency": "1", "impact": "1",
       "category": "Security", "subcategory": "Malware",
       "assigned_to": {"display_value": "Jane Analyst", "value": "analyst001"},
       "opened_by": {"display_value": "SOC Bot", "value": "soc_bot"},
       "opened_at": "2026-06-02T09:32:00Z", "updated_at": "2026-06-02T10:15:00Z",
       "caller_id": {"display_value": "John Doe", "value": "jdoe"},
       "work_notes": "Host isolated pending investigation."}]}

POST /api/now/table/incident
  → {"result": {"sys_id": "c7b3e6f2-a9d5-4c8b-4e7f-1a3f8e2d1c9b",
      "number": "INC0047899", "state": "1", "priority": "2",
      "short_description": "Auto-created by SOAR playbook",
      "opened_at": "2026-06-02T11:00:00Z"}}

PATCH /api/now/table/incident/{sys_id}
  → {"result": {"sys_id": "8f4a2b1c9d3e4f5a", "number": "INC0047821",
      "state": "6", "close_code": "Resolved", "close_notes": "Malware confirmed, host remediated.",
      "resolved_at": "2026-06-02T18:00:00Z"}}

GET /api/now/table/sys_user or /api/now/table/sys_user_group
  → {"result": [{"sys_id": "usr001", "user_name": "jdoe",
      "first_name": "John", "last_name": "Doe",
      "email": "jdoe@acmecorp.com", "active": true,
      "department": {"display_value": "Engineering"}}]}

### Jira v3  (/rest/api/3/)
GET /rest/api/3/search
  → {"issues": [{"id": "10842", "key": "SEC-842",
      "fields": {"summary": "Investigate Tor exit node connection from DESKTOP-A4K9B2Z",
        "status": {"name": "In Progress", "statusCategory": {"name": "In Progress"}},
        "assignee": {"displayName": "Jane Analyst", "emailAddress": "janalyst@acmecorp.com"},
        "priority": {"name": "High"}, "issuetype": {"name": "Security Incident"},
        "created": "2026-06-02T09:30:00Z", "updated": "2026-06-02T10:20:00Z",
        "description": {"type": "doc", "content": [{"type": "paragraph",
          "content": [{"type": "text", "text": "TOR exit node 185.220.101.47 connected to DESKTOP-A4K9B2Z"}]}]}}}],
    "total": 1, "startAt": 0, "maxResults": 50}

POST /rest/api/3/issue
  → {"id": "10899", "key": "SEC-856",
     "self": "https://jira.acmecorp.com/rest/api/3/issue/10899"}

POST /rest/api/3/issue/{key}/comment
  → {"id": "20456", "body": {"type": "doc", "version": 1,
      "content": [{"type": "paragraph", "content": [{"type": "text", "text": "..."}]}]},
     "created": "2026-06-02T11:00:00Z", "author": {"displayName": "SOAR Bot"}}

### Microsoft Graph API  (/v1.0/, /beta/)
GET /v1.0/users or /v1.0/users?$filter=...
  → {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
     "value": [
       {"id": "a3f8e2d1-4c9b-4f7e-a5d2-c8b1e9f4a7d3",
        "displayName": "John Doe", "userPrincipalName": "jdoe@acmecorp.com",
        "accountEnabled": true, "jobTitle": "Software Engineer",
        "department": "Engineering", "officeLocation": "Building A",
        "mail": "jdoe@acmecorp.com",
        "signInActivity": {"lastSignInDateTime": "2026-06-02T09:28:00Z",
          "lastSignInRequestId": "a3f8e2d1-sign-in-id"}},
       {"id": "b2c1e9f4-a7d3-4c6b-2e5f-8a1d4c7b3e6f",
        "displayName": "Jane Analyst", "userPrincipalName": "janalyst@acmecorp.com",
        "accountEnabled": true, "jobTitle": "Security Analyst"}]}

GET /v1.0/users/{id} (single user)
  → the first entry from the list above, with additional fields populated

PATCH /v1.0/users/{id} (disable account)
  → {} (Graph returns 204 No Content; return empty object)

GET /v1.0/auditLogs/signIns or /v1.0/users/{id}/authentication/signIns
  → {"@odata.context": "...$metadata#signIns",
     "value": [
       {"id": "signin-a3f8e2d1-001", "createdDateTime": "2026-06-02T09:28:00Z",
        "userDisplayName": "John Doe", "userPrincipalName": "jdoe@acmecorp.com",
        "ipAddress": "185.220.101.47", "location": {"city": "Amsterdam",
          "countryOrRegion": "NL", "geoCoordinates": {"latitude": 52.37, "longitude": 4.9}},
        "status": {"errorCode": 0, "failureReason": null},
        "riskLevelAggregated": "high", "riskLevelDuringSignIn": "high",
        "riskState": "atRisk", "clientAppUsed": "Browser"},
       {"id": "signin-a3f8e2d1-002", "createdDateTime": "2026-06-02T08:10:00Z",
        "userDisplayName": "John Doe", "userPrincipalName": "jdoe@acmecorp.com",
        "ipAddress": "10.10.14.22", "status": {"errorCode": 0},
        "riskLevelAggregated": "none", "clientAppUsed": "Microsoft Office"}]}

### AWS IAM  (?Action=... query string)
Action=ListUsers
  → {"ListUsersResponse": {"ListUsersResult": {"Users": [
      {"UserName": "deploy-svc", "UserId": "AIDAIOSFODNN7EXAMPLE01",
       "Arn": "arn:aws:iam::123456789012:user/deploy-svc",
       "CreateDate": "2023-01-15T08:00:00Z", "PasswordLastUsed": "2025-12-01T14:22:00Z"},
      {"UserName": "jdoe-admin", "UserId": "AIDAIOSFODNN7EXAMPLE02",
       "Arn": "arn:aws:iam::123456789012:user/jdoe-admin",
       "CreateDate": "2022-06-01T00:00:00Z", "PasswordLastUsed": "2026-06-02T09:00:00Z"}],
      "IsTruncated": false},
    "ResponseMetadata": {"RequestId": "a3f8e2d1-4c9b-4f7e-a5d2-c8b1e9f4a7d3"}}}

Action=GetUser → single user detail from the list above
Action=ListAccessKeys
  → {"ListAccessKeysResponse": {"ListAccessKeysResult": {"AccessKeyMetadata": [
      {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "UserName": "jdoe-admin",
       "Status": "Active", "CreateDate": "2024-06-01T00:00:00Z"}]},
    "ResponseMetadata": {"RequestId": "b2c1e9f4-a7d3-4c6b-2e5f-8a1d4c7b3e6f"}}}

Action=DisableUser or Action=DeleteLoginProfile
  → {"ResponseMetadata": {"RequestId": "c6b2e5f8-a1d4-4c7b-3e6f-2a9d5c8b4e7f"}}

### Active Directory / LDAP  (path / or /ldap/ or body contains samAccountName)
  → {"success": true, "samAccountName": "jdoe",
     "distinguishedName": "CN=John Doe,OU=Users,DC=acmecorp,DC=com",
     "displayName": "John Doe", "email": "jdoe@acmecorp.com",
     "accountEnabled": false, "lockoutTime": "2026-06-02T09:32:00Z",
     "memberOf": ["CN=Domain Users,CN=Users,DC=acmecorp,DC=com",
       "CN=Engineering,OU=Groups,DC=acmecorp,DC=com"],
     "lastLogon": "2026-06-02T09:28:00Z", "badPwdCount": 14}

### Slack  (/api/)
POST /api/chat.postMessage
  → {"ok": true, "channel": "C04SECURITY01", "ts": "1748899200.000100",
     "message": {"type": "message", "bot_id": "B04SOC0001",
       "text": "Security alert: Malware detected on DESKTOP-A4K9B2Z"}}

GET /api/conversations.list
  → {"ok": true, "channels": [
      {"id": "C04SECURITY01", "name": "security-alerts", "is_private": false},
      {"id": "C04INCIDENT01", "name": "incident-response", "is_private": true}]}

### Zscaler  (/api/v1/)
GET /api/v1/urlCategories
  → [{"id": "CUSTOM_01", "configuredName": "Known C2 Domains",
      "urls": ["evil.example.com", "185.220.101.47"],
      "dbCategorizedUrls": [], "type": "URL_CATEGORY", "editable": true}]

POST /api/v1/urlCategories/{id} → return the same object with updated urls list

GET /api/v1/users → list of Zscaler user objects

### Palo Alto Panorama  (/restapi/ or /api/)
GET /restapi/v10.1/Objects/AddressObjects
  → {"@status": "success", "@code": "19",
     "result": {"@total-count": "1", "@count": "1",
       "entry": [{"@name": "TOR-Exit-185.220.101.47",
         "ip-netmask": "185.220.101.47/32",
         "description": "Known TOR exit node — auto-blocked by SOAR",
         "tag": {"member": ["TOR", "Blocked"]}}]}}

### ReversingLabs  (/api/databrowser/ or /rl/)
GET on file hash path
  → {"rl": {"requested_hash": "a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1",
      "sha256": "a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1",
      "classification": "MALICIOUS", "threat_name": "Trojan.GenericKD.Loader",
      "threat_level": 5, "trust_factor": 0,
      "analysis": {"first_scan": "2026-05-28T14:22:00Z",
        "last_scan": "2026-06-02T08:00:00Z",
        "sample_available": true}}}

For any unrecognized path: infer the vendor from URL structure and return a
plausible shaped response grounded in the incident context above.
Never return {"data": [], "status": "ok"} — always synthesize something meaningful.
"""


def cache_key(method: str, path: str, query: str, body: bytes) -> str:
    h = hashlib.sha256()
    h.update(method.encode())
    h.update(b"\n")
    h.update(path.encode())
    h.update(b"\n")
    h.update(urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(query))).encode())
    h.update(b"\n")
    h.update(body or b"")
    return h.hexdigest()[:32]


def cache_load(key: str):
    p = CACHE_DIR / f"{key}.json"
    if p.exists():
        return json.loads(p.read_text())["payload"]
    return None


def cache_save(key: str, payload, meta: dict):
    p = CACHE_DIR / f"{key}.json"
    p.write_text(json.dumps({"meta": meta, "payload": payload}, indent=2))


def synth(method: str, path: str, query: str, body: bytes):
    body_str = body.decode("utf-8", "replace") if body else ""
    user_msg = (
        f"Incoming request:\n"
        f"  method: {method}\n"
        f"  path:   {path}\n"
        f"  query:  {query}\n"
        f"  body:   {body_str[:2000]}\n\n"
        f"Return the JSON response body the vendor would send."
    )

    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": user_msg}]}],
        inferenceConfig={"maxTokens": 4096, "temperature": 0.4},
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()

    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip().rstrip("`").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"data": [], "status": "ok", "_mock_note": "LLM returned non-JSON, falling back"}


class Handler(BaseHTTPRequestHandler):
    def _serve(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""

        key = cache_key(method, parsed.path, parsed.query, body)
        cached = cache_load(key)
        if cached is not None:
            payload, source = cached, "cache"
        else:
            try:
                payload = synth(method, parsed.path, parsed.query, body)
                cache_save(key, payload, {"method": method, "path": parsed.path, "query": parsed.query})
            except Exception as e:
                payload = {"data": [], "status": "ok", "_mock_error": str(e)[:200]}
            source = "bedrock"

        out = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("X-Mock-Source", source)
        self.send_header("X-Mock-CacheKey", key)
        self.end_headers()
        self.wfile.write(out)
        sys.stderr.write(f"[{source}] {method} {parsed.path} -> {len(out)}B\n")

    def do_GET(self):    self._serve("GET")
    def do_POST(self):   self._serve("POST")
    def do_PUT(self):    self._serve("PUT")
    def do_DELETE(self): self._serve("DELETE")
    def do_PATCH(self):  self._serve("PATCH")

    def log_message(self, fmt, *args):
        pass


def preflight():
    try:
        bedrock.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "Reply with the word OK."}]}],
            inferenceConfig={"maxTokens": 8},
        )
    except Exception as e:
        sys.stderr.write(f"Bedrock preflight failed: {e}\n")
        sys.stderr.write("Check AWS creds and BEDROCK_MODEL_ID / BEDROCK_REGION.\n")
        sys.exit(1)


def main():
    print(f"LLM mock server")
    print(f"  port:   {PORT}")
    print(f"  model:  {MODEL_ID}")
    print(f"  region: {REGION}")
    print(f"  cache:  {CACHE_DIR.resolve()}")
    print("  verifying Bedrock creds...", end=" ", flush=True)
    preflight()
    print("ok\n")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
