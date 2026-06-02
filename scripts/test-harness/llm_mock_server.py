#!/usr/bin/env python3
"""
LLM-backed mock vendor API server. Uses Amazon Bedrock (Opus 4.8 by default)
to synthesize realistic, context-aware vendor responses on demand.

The server extracts the primary indicator (IP, domain, hash, email, username)
from every inbound request and asks the model to assess it and respond
accordingly. Private/RFC1918 IPs get clean responses; known-bad ranges get
malicious ones; usernames get account history; everything else is plausible.
Responses are cached on disk — identical requests are served from cache and
never hit Bedrock twice.

Env vars:
    BEDROCK_MODEL_ID    default: us.anthropic.claude-opus-4-8
    BEDROCK_REGION      default: us-west-2
    CACHE_DIR           default: ./cache
    PORT                default: 8080

Run:
    pip install boto3
    python3 llm_mock_server.py

Smoke tests:
    curl -s http://localhost:8080/api/v3/ip_addresses/192.168.1.1 | jq
    curl -s http://localhost:8080/api/v3/ip_addresses/185.220.101.47 | jq
    curl -s http://localhost:8080/v3/community/8.8.8.8 | jq
    curl -s http://localhost:8080/api/now/table/incident | jq

Cache:
    rm -rf cache/   # force fresh LLM calls
    Per-file JSON, sha256-keyed. Inspect with: cat cache/<key>.json | jq .
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import boto3

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-opus-4-8")
REGION = os.environ.get("BEDROCK_REGION", "us-west-2")
CACHE_DIR = Path(os.environ.get("CACHE_DIR", "./cache"))
PORT = int(os.environ.get("PORT", "8080"))

CACHE_DIR.mkdir(parents=True, exist_ok=True)
bedrock = boto3.client("bedrock-runtime", region_name=REGION)


# ── Indicator extraction ────────────────────────────────────────────────────

def _extract_indicator(path: str, query: str, body: str) -> dict:
    """Pull the primary security indicator out of the request."""
    combined = f"{path}?{query} {body[:1000]}"

    # IPv4 in URL path (VirusTotal /ip_addresses/x.x.x.x, GreyNoise /community/x.x.x.x)
    m = re.search(r"/ip[_\-]addresses?/([0-9]{1,3}(?:\.[0-9]{1,3}){3})", path)
    if m:
        return {"type": "ip", "value": m.group(1)}

    m = re.search(r"/community/([0-9]{1,3}(?:\.[0-9]{1,3}){3})", path)
    if m:
        return {"type": "ip", "value": m.group(1)}

    m = re.search(r"/noise/context/([0-9]{1,3}(?:\.[0-9]{1,3}){3})", path)
    if m:
        return {"type": "ip", "value": m.group(1)}

    # SHA-256 / MD5 / SHA-1 hash in path (VirusTotal /files/<hash>)
    m = re.search(r"/files?/([a-fA-F0-9]{32,64})", path)
    if m:
        return {"type": "hash", "value": m.group(1).lower()}

    # Domain in path
    m = re.search(r"/domains?/([a-zA-Z0-9][a-zA-Z0-9\-\.]{3,})", path)
    if m:
        return {"type": "domain", "value": m.group(1)}

    # URL scan
    m = re.search(r"/urls?/([A-Za-z0-9+/=]{10,})", path)
    if m:
        return {"type": "url_encoded", "value": m.group(1)}

    # Email / UPN anywhere in combined string
    m = re.search(r"\b([\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,})\b", combined)
    if m:
        return {"type": "email", "value": m.group(1).lower()}

    # IPv4 in query params or JSON body
    m = re.search(
        r'"(?:ip|sourceAddress|destination_address|remoteAddress|clientIp)"'
        r'\s*:\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"', body
    )
    if m:
        return {"type": "ip", "value": m.group(1)}

    m = re.search(r"(?:ip|address)=([0-9]{1,3}(?:\.[0-9]{1,3}){3})", query)
    if m:
        return {"type": "ip", "value": m.group(1)}

    # Username in body
    m = re.search(r'"(?:username|userName|samAccountName|user_name)"\s*:\s*"([^"]{3,})"', body)
    if m:
        return {"type": "username", "value": m.group(1)}

    return {"type": "unknown", "value": ""}


def _assess_indicator(indicator: dict) -> str:
    """Return a brief reputation assessment the model can use for calibration."""
    itype = indicator["type"]
    value = indicator["value"]

    if itype == "ip":
        try:
            addr = ipaddress.ip_address(value)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return (
                    f"{value} is a PRIVATE / RFC1918 address. "
                    "Return: benign, 0 malicious detections, no threat intel hits."
                )
            if addr.is_multicast or addr.is_reserved:
                return f"{value} is a reserved/multicast address. Return benign."
        except ValueError:
            pass

        # Known-bad CIDR blocks (Tor, bulletproof hosting, scanning infra)
        BAD_PREFIXES = (
            "185.220.", "199.249.", "23.129.64.", "176.10.99.", "5.188.",
            "45.142.", "193.32.162.", "194.165.", "80.82.", "91.108.",
        )
        if any(value.startswith(p) for p in BAD_PREFIXES):
            return (
                f"{value} is a KNOWN MALICIOUS IP (Tor exit node / bulletproof hosting). "
                "Return: 40-60 malicious detections out of 72 engines, "
                "classification=malicious, noise=true, riot=false."
            )

        # Classify the last octet to vary noise level realistically
        try:
            last = int(value.split(".")[-1])
            noise = "low" if last % 3 == 0 else "moderate"
        except Exception:
            noise = "low"
        return (
            f"{value} is a PUBLIC IP with {noise} noise profile. "
            "Return: 2-8 malicious detections, moderate reputation score."
        )

    if itype == "hash":
        # Hashes that look randomised/high-entropy → suspicious
        entropy_chars = len(set(value)) / max(len(value), 1)
        if entropy_chars > 0.55:
            return (
                f"Hash {value[:16]}... appears high-entropy / obfuscated. "
                "Return: 50-65 malicious detections, classification=malicious trojan/loader."
            )
        return (
            f"Hash {value[:16]}... is unknown. "
            "Return: 0-4 malicious detections, undetected by most engines."
        )

    if itype == "domain":
        BENIGN = ("google", "microsoft", "amazon", "apple", "cloudflare", "elastic")
        if any(b in value.lower() for b in BENIGN):
            return f"{value} is a KNOWN-LEGITIMATE domain. Return: 0 detections, benign."
        SUSPICIOUS_TLDS = (".xyz", ".tk", ".top", ".gq", ".ml", ".cf")
        if any(value.endswith(t) for t in SUSPICIOUS_TLDS):
            return (
                f"{value} has a SUSPICIOUS TLD. "
                "Return: 15-35 malicious detections, phishing/malware category."
            )
        return f"{value} is an UNKNOWN domain. Return: 0-8 detections, low reputation."

    if itype in ("email", "username"):
        return (
            f"User identifier: {value}. Include 4-8 records of their account history "
            "(recent tickets, sign-ins, events). Mix normal activity with 1-2 anomalies."
        )

    return "Unknown indicator. Return a plausible response based on vendor and request path."


# ── System prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a mock vendor REST API for security orchestration and SOAR testing.
You receive HTTP requests from automated workflows and return realistic JSON that looks
exactly like what the real vendor would return.

CRITICAL RULES:
1. Output ONLY valid JSON. No prose, no markdown fences, no explanation.
2. The caller will tell you the extracted indicator and its reputation assessment.
   Use that assessment to calibrate every numeric score, count, and verdict in your response.
3. NEVER return null for reputation scores, detection counts, PhishTank verdicts,
   VirusTotal last_analysis_stats, GreyNoise classifications, or any count field.
   Every numeric field must be a real integer or float.
4. For LIST or SEARCH operations: always return 3-8 records. Never return an empty array
   for searches that should have results (ticket history, Splunk events, user sign-ins).
5. For user-related requests (by email, username, or UUID): embed 4-8 historical records
   (tickets raised, events, sign-ins, alerts) that tell a coherent story about that user.
6. For destructive actions (disable/block/quarantine/delete): return a success envelope.
7. For OAuth/token endpoints: return a realistic bearer token with expires_in.

VENDOR SCHEMAS — match by URL path prefix and method:

### VirusTotal v3  (/api/v3/)
GET /api/v3/ip_addresses/{ip}
  → {"data": {"id": "{ip}", "type": "ip_address", "attributes": {
      "network": "{cidr}/24", "country": "{2-letter CC}", "continent": "{CC}",
      "asn": {asn_number}, "as_owner": "{org name}",
      "regional_internet_registry": "{RIR}",
      "last_analysis_stats": {"harmless": {h}, "malicious": {m}, "suspicious": {s},
        "undetected": {u}, "timeout": 0},
      "last_analysis_results": {
        "Fortinet": {"category": "{malicious|harmless}", "result": "{tag|clean}",
          "method": "blacklist", "engine_name": "Fortinet"},
        "Kaspersky": {"category": "{malicious|harmless}", "result": "{tag|clean}",
          "method": "blacklist", "engine_name": "Kaspersky"},
        "Palo Alto Networks": {"category": "{malicious|harmless}", "result": "{tag|clean}",
          "method": "blacklist", "engine_name": "Palo Alto Networks"}
      },
      "reputation": {signed_integer}, "tags": [{tag}, ...],
      "last_modification_date": {unix_ts}}}}

GET /api/v3/files/{hash}
  → {"data": {"id": "{hash}", "type": "file", "attributes": {
      "meaningful_name": "{filename}.{ext}",
      "type_description": "Win32 EXE",
      "size": {bytes},
      "md5": "{32-char hex}", "sha1": "{40-char hex}", "sha256": "{hash}",
      "last_analysis_stats": {"harmless": {h}, "malicious": {m}, "suspicious": {s},
        "undetected": {u}, "timeout": 0},
      "last_analysis_date": {unix_ts},
      "tags": [{tag}, ...],
      "names": ["{name1}", "{name2}"],
      "crowdsourced_context": [{"source": "Mandiant", "title": "{threat group} loader",
        "severity": "{HIGH|CRITICAL}", "details": "{description}"}]}}}

GET /api/v3/domains/{domain}
  → {"data": {"id": "{domain}", "type": "domain", "attributes": {
      "last_analysis_stats": {"harmless": {h}, "malicious": {m}, "suspicious": {s},
        "undetected": {u}},
      "reputation": {signed_integer},
      "categories": {{"Forcepoint ThreatSeeker": "{category}"}},
      "last_dns_records": [{{"type": "A", "value": "{ip}", "ttl": 300}}],
      "phishing_detection": {{"PhishTank": {{"verdict": "{phishing|clean}",
        "score": {0_to_100}}}, "OpenPhish": {{"verdict": "{phishing|clean}"}}}}
    }}}

POST /api/v3/files or /api/v3/urls
  → {"data": {"type": "analysis", "id": "{uuid}",
      "links": {"self": "https://www.virustotal.com/api/v3/analyses/{uuid}"}}}

### GreyNoise  (/v3/community/, /v2/)
GET /v3/community/{ip}
  → {"ip": "{ip}", "noise": {true|false}, "riot": {true|false},
     "classification": "{malicious|benign|unknown}",
     "name": "{org or Tor Exit Node}", "last_seen": "{YYYY-MM-DD}",
     "link": "https://viz.greynoise.io/ip/{ip}",
     "message": "{one-sentence description}"}

GET /v2/noise/context/{ip}
  → {"ip": "{ip}", "seen": {bool}, "classification": "{classification}",
     "first_seen": "{date}", "last_seen": "{date}",
     "tags": ["{tag}", ...], "actor": "{actor or unknown}",
     "spoofable": false, "bot": {bool}, "vpn": {bool},
     "metadata": {"country": "{country}", "country_code": "{CC}",
       "city": "{city}", "organization": "{org}", "asn": "AS{number}"},
     "raw_data": {"scan": [{"port": {port}, "protocol": "TCP"}, ...]}}

### Splunk REST API  (/services/)
POST /services/search/v2/jobs or /services/search/jobs
  → {"sid": "1{10-digit-unix}.{5-digit-rand}_{UUID-style}", "messages": []}

GET /services/search/v2/jobs/{sid} or /services/search/jobs/{sid}
  → {"entry": [{"name": "{sid}", "content": {
      "dispatchState": "DONE", "isDone": true,
      "eventCount": {5-50}, "resultCount": {5-20}, "scanCount": {50000-500000},
      "runDuration": {0.5-5.0}, "doneProgress": 1.0}}]}

GET .../results
  → {"preview": false, "offset": 0,
     "results": [
       {"_time": "{ISO8601}", "host": "{hostname}", "source": "{source}",
        "sourcetype": "{sourcetype}", "index": "{index}",
        {relevant_fields_for_the_search}: "{value}", "_raw": "{log_line}"},
       ... 5-15 records mixing normal and anomalous activity ...
     ]}
   For auth searches: EventCode 4624/4625, Account_Name, src_ip, Workstation_Name.
   For process searches: EventCode 4688, Process_Name, Parent_Process_Name, CommandLine.
   For network searches: src_ip, dest_ip, dest_port, bytes_out, protocol.
   For user activity: include 1-2 anomalous entries (off-hours, unusual src_ip, new process).

POST /services/search/v2/jobs/{sid}/results/preview (notable events)
  → Return same shape but results are Splunk ES notable event objects with:
    {"_time", "rule_name", "urgency", "status", "src", "dest", "user",
     "orig_time", "event_id", "count": {2-15}}
   NEVER return count=0 or empty results array for notable event searches.

### ServiceNow  (/api/now/)
GET /api/now/table/{table_name}  (ANY table — incident, problem, change_request,
  sc_req_item, sn_si_incident, sc_task, syslog_transaction_failed, etc.)
  → {"result": [
      ... 3-8 records relevant to any user/IP/asset mentioned in the query ...
    ]}
  Each record must have sys_id, number (format depends on table: INC, PRB, CHG, RITM, etc.),
  short_description, state, priority, opened_at, assigned_to, caller_id.
  Include records that tell a story — mix resolved and open tickets. NEVER return empty result[].
  For related-ticket searches (sysparm_query contains a username or IP):
    return 3-5 tickets that involve that entity.

### Jira v3  (/rest/api/3/)
GET /rest/api/3/search
  → {"issues": [{4-8 issues}], "total": {4-8}, "startAt": 0, "maxResults": 50}
  Each issue: id, key (SEC-NNN), fields.summary, fields.status.name,
  fields.assignee.displayName, fields.priority.name, fields.created.
  Match the search query context — if the JQL mentions a user or IP, issues should relate to it.

POST /rest/api/3/issue
  → {"id": "{5-digit}", "key": "SEC-{3-digit}", "self": "https://jira.{domain}/rest/api/3/issue/{id}"}

### Microsoft Graph API  (/v1.0/, /beta/, /users)
GET .../users or /users
  → {"@odata.context": "...$metadata#users", "value": [
      {3-5 user objects each with id(UUID), displayName, userPrincipalName,
       accountEnabled, jobTitle, department, mail, signInActivity.lastSignInDateTime}
    ]}

GET .../users/{id_or_email} (single user)
  → single user object with all fields populated

GET .../signIns or .../auditLogs/signIns
  → {"value": [
      {5-8 sign-in records with id, createdDateTime, userDisplayName,
       userPrincipalName, ipAddress, location.city, location.countryOrRegion,
       status.errorCode(0=success), riskLevelAggregated, clientAppUsed}
    ]}
  Mix normal (corporate IP, low risk) with 1-2 anomalous (foreign IP, high risk).

PATCH .../users/{id}  → {} (Graph returns 204, return empty object)

### CrowdStrike Falcon  (/oauth2/, /devices/, /detects/, /incidents/)
POST /oauth2/token
  → {"access_token": "cs-{base64-like-string}", "expires_in": 1799, "token_type": "bearer"}

GET /devices/queries/devices/v1
  → {"meta": {"query_time": 0.018, "trace_id": "{uuid}"},
     "resources": ["{15-char-hex}", "{15-char-hex}"], "errors": []}

GET /devices/entities/devices/v1
  → {"meta": {"query_time": 0.021, "trace_id": "{uuid}"},
     "resources": [{device object with device_id, hostname, local_ip, external_ip,
       os_version, agent_version, status, first_seen, last_seen, machine_domain,
       bios_manufacturer, os_build, platform_name}],
     "errors": []}

GET /detects/queries/detects/v1
  → {"meta": {"trace_id": "{uuid}"}, "resources": ["ldt:{hex}:1", "ldt:{hex}:2"], "errors": []}

POST /devices/entities/devices-actions/v2
  → {"id": "{uuid}", "resources": [{"id": "{device_id}", "action_was_applied": true}], "errors": []}

### AWS IAM  (query string has Action=)
Action=ListUsers
  → {"ListUsersResponse": {"ListUsersResult": {"Users": [
      {3-5 user objects: UserName, UserId(AIDA...), Arn, CreateDate, PasswordLastUsed}
    ], "IsTruncated": false},
    "ResponseMetadata": {"RequestId": "{uuid}"}}}

Action=GetUser  → single user from the list
Action=ListAccessKeys  → AccessKeyMetadata array with AccessKeyId(AKIA...), Status, CreateDate

### Active Directory / LDAP  (path / or /ldap/ or body references samAccountName/DN)
  → {"success": true, "samAccountName": "{username}",
     "distinguishedName": "CN={DisplayName},OU=Users,DC={domain},DC=com",
     "displayName": "{Full Name}", "email": "{email}",
     "accountEnabled": {bool}, "lockoutTime": "{ISO8601 or null}",
     "memberOf": ["CN=Domain Users,...", "CN={dept},OU=Groups,..."],
     "lastLogon": "{ISO8601}", "badPwdCount": {0-20},
     "passwordLastSet": "{ISO8601}"}

### Slack  (/api/)
POST /api/chat.postMessage
  → {"ok": true, "channel": "{channel_id}", "ts": "{unix_ts}.{6-digit}",
     "message": {"type": "message", "bot_id": "B{8-char}", "text": "{message_text}"}}

### Zscaler  (/api/v1/)
GET /api/v1/urlCategories
  → [{"id": "CUSTOM_{NN}", "configuredName": "{category name}",
      "urls": ["{url1}", "{url2}"], "type": "URL_CATEGORY", "editable": true}]

POST /api/v1/urlCategories/{id}  → updated category object

### Palo Alto Panorama  (/restapi/, /api/)
GET /restapi/v10.1/Objects/AddressObjects
  → {"@status": "success", "@code": "19",
     "result": {"@total-count": "2", "entry": [
       {"@name": "{indicator-based name}", "ip-netmask": "{ip}/32",
        "description": "{context}", "tag": {"member": ["{tag1}", "{tag2}"]}}
     ]}}

### ReversingLabs  (/api/databrowser/, /rl/)
GET on file hash path
  → {"rl": {"requested_hash": "{hash}", "sha256": "{hash}",
      "classification": "{MALICIOUS|KNOWN|UNKNOWN}",
      "threat_name": "{ThreatFamily.Type}",
      "threat_level": {0-5}, "trust_factor": {0-5},
      "analysis": {"first_scan": "{ISO8601}", "last_scan": "{ISO8601}",
        "sample_available": true}}}

### PhishTank / OpenPhish  (/checkurl/, /api/, /feed/)
POST or GET on phish-check endpoints
  → {"in_database": {true|false}, "phish_id": "{id or null}",
     "phish_detail_page": "{url or null}",
     "valid": {true|false}, "verified": {true|false},
     "verified_at": "{ISO8601 or null}",
     "target": "{brand name or null}"}
  If the URL/domain looks suspicious: in_database=true, valid=true, verified=true.
  If benign: in_database=false, valid=false.

### Generic / fallback
If the path doesn't match any vendor above: infer from URL structure and HTTP method,
return a plausible vendor-shaped JSON response. Never return {"data":[], "status":"ok"}.
"""


# ── Cache ────────────────────────────────────────────────────────────────────

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


# ── LLM synthesis ────────────────────────────────────────────────────────────

def synth(method: str, path: str, query: str, body: bytes) -> dict:
    body_str = body.decode("utf-8", "replace") if body else ""

    indicator = _extract_indicator(path, query, body_str)
    assessment = _assess_indicator(indicator)

    user_msg = (
        f"HTTP request to mock:\n"
        f"  method: {method}\n"
        f"  path:   {path}\n"
        f"  query:  {query or '(none)'}\n"
        f"  body:   {body_str[:2000] or '(empty)'}\n\n"
        f"Extracted indicator: {indicator['type']} = {indicator['value']!r}\n"
        f"Reputation assessment: {assessment}\n\n"
        f"Return the complete JSON response body the vendor would send for this request."
    )

    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": user_msg}]}],
        inferenceConfig={"maxTokens": 4096},
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
        return {"_mock_error": "LLM returned non-JSON", "_raw": text[:200]}


# ── HTTP server ───────────────────────────────────────────────────────────────

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
                cache_save(key, payload, {
                    "method": method,
                    "path": parsed.path,
                    "query": parsed.query,
                })
            except Exception as e:
                payload = {"_mock_error": str(e)[:200]}
            source = "bedrock"

        out = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("X-Mock-Source", source)
        self.send_header("X-Mock-CacheKey", key)
        self.end_headers()
        self.wfile.write(out)
        sys.stderr.write(f"[{source:6s}] {method} {parsed.path} -> {len(out)}B\n")

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
        sys.stderr.write(f"Model: {MODEL_ID}  Region: {REGION}\n")
        sys.stderr.write("Override with BEDROCK_MODEL_ID / BEDROCK_REGION env vars.\n")
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
    print("Ready. Logs: [bedrock] = fresh LLM call, [cache ] = served from disk\n")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
