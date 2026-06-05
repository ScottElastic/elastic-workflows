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

import datetime
import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
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


# ── Canonical scenario (anchors cross-vendor coherence) ──────────────────────
# When a request mentions any of these indicators, every vendor response gets
# pinned to the same story: malware on jdoe's host calling out to a TOR exit.
# Free-form indicators fall back to the generic assessment path.

TODAY = "2026-06-03"
SCENARIO_START = "2026-06-02T08:55:00Z"   # phishing email arrives
SCENARIO_DETECTION = "2026-06-02T09:32:00Z"  # CrowdStrike detection

# Epoch window for *_date integer fields. Lower bound is 2025-01-01 (gives
# enough history for "user created N months ago" style fields). Upper bound is
# derived from TODAY so the SYSTEM_PROMPT stays in sync if TODAY moves forward.
_TODAY_EPOCH = int(datetime.datetime.strptime(TODAY, "%Y-%m-%d")
                   .replace(tzinfo=datetime.timezone.utc).timestamp())
EPOCH_LOWER = 1735689600          # 2025-01-01 00:00 UTC
EPOCH_UPPER = _TODAY_EPOCH        # today, 00:00 UTC

# Pre-computed scenario epochs. The LLM's epoch arithmetic for post-2024 dates
# is unreliable — it consistently lands one year early. Compute these here and
# pass them in so the model can copy them verbatim into *_date integer fields.
_SCENARIO_START_EPOCH = int(datetime.datetime.fromisoformat(
    SCENARIO_START.replace("Z", "+00:00")).timestamp())
_SCENARIO_DETECTION_EPOCH = int(datetime.datetime.fromisoformat(
    SCENARIO_DETECTION.replace("Z", "+00:00")).timestamp())

CANONICAL = {
    "ip":            "185.220.101.47",
    "ip_asn":        208294,
    "ip_as_owner":   "Zwiebelfreunde e.V.",
    "ip_country":    "DE",
    "ip_city":       "Berlin",
    "ip_network":    "185.220.101.0/24",
    "internal_ip":   "10.10.14.22",
    "host":          "DESKTOP-A4K9B2Z",
    "host_domain":   "ACMECORP",
    "host_os":       "Windows 10 Enterprise 22H2",
    "user":          "jdoe@acmecorp.com",
    "user_display":  "John Doe",
    "user_sam":      "jdoe",
    "second_user":   "janalyst@acmecorp.com",
    "second_display": "Jane Analyst",
    "sha256":        "a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1",
    "md5":           "a3f8e2d14c9b4f7e",
    "sha1":          "a3f8e2d14c9b4f7ea5d2c8b1",
    "malware_name":  "invoice_march.exe",
    "malware_family": "TrickBot.Loader.Gen",
    "domain":        "evil.example.com",
    "message_id":    "<4d2a9f3b@mail.acmecorp.com>",
    "sender":        "hr-noreply@acmecorp-invoices.com",
    "company":       "AcmeCorp",
    "tenant_domain": "acmecorp.com",
}

CANONICAL_INDICATORS = {
    CANONICAL["ip"], CANONICAL["internal_ip"], CANONICAL["host"],
    CANONICAL["user"], CANONICAL["second_user"], CANONICAL["user_sam"],
    CANONICAL["sha256"], CANONICAL["md5"], CANONICAL["sha1"],
    CANONICAL["domain"], CANONICAL["message_id"], CANONICAL["sender"],
}

SCENARIO_BLOCK = f"""
CANONICAL INCIDENT — anchor every response that touches any of these indicators to this story:

  Date: {TODAY}. Incident detected {SCENARIO_DETECTION}.
  Reference epochs (use these EXACT integers in *_date fields — do not recompute):
    today_epoch:                {_TODAY_EPOCH}            ({TODAY})
    scenario_start_epoch:       {_SCENARIO_START_EPOCH}            ({SCENARIO_START})
    scenario_detection_epoch:   {_SCENARIO_DETECTION_EPOCH}            ({SCENARIO_DETECTION})
    valid epoch range:          {EPOCH_LOWER} to {EPOCH_UPPER}

  User:        {CANONICAL['user']} (display "{CANONICAL['user_display']}", SAM "{CANONICAL['user_sam']}")
  Second user: {CANONICAL['second_user']} (display "{CANONICAL['second_display']}")
  Host:        {CANONICAL['host']} ({CANONICAL['host_os']}, domain {CANONICAL['host_domain']})
  Internal IP: {CANONICAL['internal_ip']}
  External IP: {CANONICAL['ip']} (TOR exit, ASN {CANONICAL['ip_asn']} {CANONICAL['ip_as_owner']}, {CANONICAL['ip_country']}/{CANONICAL['ip_city']}, network {CANONICAL['ip_network']})
  Malware:     {CANONICAL['malware_name']} (family {CANONICAL['malware_family']})
  SHA256:      {CANONICAL['sha256']}
  MD5:         {CANONICAL['md5']}
  SHA1:        {CANONICAL['sha1']}
  Phish email: from {CANONICAL['sender']} to {CANONICAL['user']}, msg-id {CANONICAL['message_id']}
  Bad domain:  {CANONICAL['domain']}
  Tenant:      {CANONICAL['tenant_domain']} ({CANONICAL['company']})

Rules when ANY indicator above appears in the request:
- All ASN / country / org / family / hostname fields MUST match this scenario exactly.
- Verdict: malicious for {CANONICAL['ip']}, {CANONICAL['sha256']}, {CANONICAL['domain']}, {CANONICAL['sender']}.
- Verdict: benign-but-investigated for {CANONICAL['user']}, {CANONICAL['host']}, {CANONICAL['internal_ip']}.
- All dates fall between 2025-01-01 and {TODAY}. NEVER emit a date in 2023 or 2024.
- "Last activity" fields (last_analysis_date, last_modification_date, last_seen,
  last_observed, updated_at) for the malicious indicators should fall within the
  72 hours BEFORE {TODAY} — these IOCs are actively being analyzed right now.
- Historical records about {CANONICAL['user']} or {CANONICAL['host']} should reference the phishing email,
  the malware execution at {SCENARIO_DETECTION}, or supporting recent activity.
- The reported caller, assignee, displayName, attacker_name fields are drawn from the names above —
  not random new identities. NEVER invent unrelated users like jrowland, msalazar,
  kpatel, jsmith, etc. when a canonical user/host/IP appears in the request.
- Workstation_Name and host fields for log entries must be {CANONICAL['host']} when
  the scenario is anchored; do NOT use generic FIN-WS-XXXX or DESKTOP-XXXXX names.

Vendor-specific scenario anchors (schema format is still required):
- Recorded Future /v2/ip/{CANONICAL['ip']}: data.risk.score=97, criticalityLabel="Malicious",
  evidenceDetails must include "Tor Exit Node" and "Malware C2" rules.
  data.relatedEntities must include {CANONICAL['sha256']} (Hash) and {CANONICAL['domain']} (InternetDomainName).
- Recorded Future /v2/hash/{CANONICAL['sha256']}: data.risk.score=99, criticalityLabel="Malicious",
  evidenceDetails must include "Malware Sample" rule referencing {CANONICAL['malware_family']}.
- Anomali ThreatStream /api/v2/intelligence for canonical IP:
  objects[0].confidence=98, severity="very-high", threat_type="c2", itype="mal_ip".
- TruSTAR /api/1.3/indicators/search for canonical IP: priorityScore="CRITICAL",
  reportId must be a stable alphanumeric ID (not random — reuse same value for same indicator).
- PassiveTotal /v2/whois for {CANONICAL['domain']}: organization="Privacy Protect, LLC",
  country="US", registrar="NameSilo", registered="2026-05-10T00:00:00Z".
- GreyNoise /v3/experimental/gnql (any canonical-anchored query): include {CANONICAL['ip']} in data[],
  with classification="malicious", tags=["Tor Exit Node","C2","TrickBot"], rdns="".
"""


# ── Request correlation (stateful) ──────────────────────────────────────────
# Some vendor APIs are two-step: a POST creates a resource (Splunk search,
# urlscan submission, VT analysis), returning an opaque id; a follow-up GET
# fetches results by that id. The follow-up has no indicator in the URL or
# body, so without correlation the LLM has nothing to anchor on — and tends
# to hallucinate an unrelated story (e.g. Finance-team Splunk events for a
# search that was about the canonical TOR IP).
#
# We keep a small in-memory map from (kind, id) → originating request body
# and reference it during synth(). The map is bounded by REQUEST_TRACE_LIMIT
# to keep memory steady across long sessions.

REQUEST_TRACE_LIMIT = 1024
_request_trace: dict[tuple[str, str], dict] = {}
_request_trace_order: list[tuple[str, str]] = []
_request_trace_lock = threading.Lock()


def _trace_remember(kind: str, ident: str, origin_path: str, origin_body: str) -> None:
    if not ident:
        return
    key = (kind, ident)
    with _request_trace_lock:
        if key in _request_trace:
            _request_trace_order.remove(key)
        elif len(_request_trace_order) >= REQUEST_TRACE_LIMIT:
            old = _request_trace_order.pop(0)
            _request_trace.pop(old, None)
        _request_trace[key] = {"origin_path": origin_path, "origin_body": origin_body[:2000]}
        _request_trace_order.append(key)


def _trace_lookup(kind: str, ident: str) -> dict:
    return _request_trace.get((kind, ident), {})


def _correlate_request(method: str, path: str, body_str: str) -> dict:
    """Return originating-request metadata for stateful lookups, or {}."""
    # Splunk: /services/search/v2/jobs/{sid} or .../{sid}/results
    m = re.match(r"^/services/search/v[12]?/?jobs/([^/]+)(?:/results)?/?$", path)
    if m and method == "GET":
        return _trace_lookup("splunk_job", m.group(1))
    m = re.match(r"^/services/search/jobs/([^/]+)(?:/results)?/?$", path)
    if m and method == "GET":
        return _trace_lookup("splunk_job", m.group(1))
    # urlscan-io: /api/v1/result/{uuid}
    m = re.match(r"^/api/v1/result/([0-9a-f-]+)/?$", path)
    if m and method == "GET":
        return _trace_lookup("urlscan", m.group(1))
    # VirusTotal: /api/v3/analyses/{id}
    m = re.match(r"^/api/v3/analyses/([^/]+)/?$", path)
    if m and method == "GET":
        return _trace_lookup("vt_analysis", m.group(1))
    return {}


def _trace_creation(method: str, path: str, body_str: str, payload: object) -> None:
    """If this request created a long-lived resource, remember the originator."""
    if not isinstance(payload, dict):
        return
    # Splunk search creation — returns {"sid": "..."}
    if method == "POST" and re.match(r"^/services/search/(v[12]/)?jobs/?$", path):
        sid = payload.get("sid")
        if sid:
            _trace_remember("splunk_job", str(sid), path, body_str)
        return
    # urlscan submission — returns {"uuid": "..."} typically
    if method == "POST" and path.startswith("/api/v1/scan"):
        uid = payload.get("uuid") or payload.get("scan_id")
        if uid:
            _trace_remember("urlscan", str(uid), path, body_str)
        return
    # VirusTotal URL/file submission — returns {"data": {"id": "..."}}
    if method == "POST" and (path == "/api/v3/urls" or path == "/api/v3/files"):
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, dict) and data.get("id"):
            _trace_remember("vt_analysis", str(data["id"]), path, body_str)
        return


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


def _request_touches_scenario(path: str, query: str, body: str) -> bool:
    """True if any canonical indicator appears in the request — anchor the response."""
    blob = f"{path} {query} {body[:4000]}".lower()
    for ind in CANONICAL_INDICATORS:
        if ind.lower() in blob:
            return True
    return False


def _assess_indicator(indicator: dict) -> str:
    """Return a brief reputation assessment the model can use for calibration."""
    itype = indicator["type"]
    value = indicator["value"]

    # Canonical-scenario overrides — pin verdict regardless of heuristic.
    if value == CANONICAL["ip"]:
        return (
            f"{value} is the SCENARIO TOR EXIT NODE. Return: 45-55 malicious detections out of ~72, "
            f"ASN {CANONICAL['ip_asn']} ({CANONICAL['ip_as_owner']}), country {CANONICAL['ip_country']}, "
            f"network {CANONICAL['ip_network']}, tags include tor-exit-node, c2-callback, "
            f"reputation strongly negative."
        )
    if value == CANONICAL["internal_ip"]:
        return (
            f"{value} is the INTERNAL workstation IP for host {CANONICAL['host']}. "
            "Treat as RFC1918 / benign. Any directory results should belong to the scenario user."
        )
    if value == CANONICAL["sha256"] or value == CANONICAL["md5"] or value == CANONICAL["sha1"]:
        return (
            f"Hash {value[:16]}... is the SCENARIO MALWARE SAMPLE ({CANONICAL['malware_name']}, "
            f"family {CANONICAL['malware_family']}). Return: 55-65 malicious detections out of ~72, "
            "classification=malicious trojan/loader, names include "
            f"'{CANONICAL['malware_name']}'. crowdsourced_context must list Mandiant / Microsoft / "
            "CrowdStrike severity HIGH or CRITICAL."
        )
    if value.lower() == CANONICAL["domain"].lower():
        return (
            f"{value} is the SCENARIO MALICIOUS DOMAIN (registered for the phishing campaign). "
            f"Return: 25-40 malicious detections, categories=phishing,malware, resolved to "
            f"{CANONICAL['ip']}, registrar/whois recent (within 30 days)."
        )
    if value.lower() in (CANONICAL["user"].lower(), CANONICAL["second_user"].lower(),
                         CANONICAL["user_sam"].lower()):
        return (
            f"User {value} is the SCENARIO user. Embed 4-8 historical records: "
            f"sign-ins from {CANONICAL['internal_ip']} (low risk), the phishing email arrival "
            f"at {SCENARIO_START}, CrowdStrike detection at {SCENARIO_DETECTION}, and 1-2 "
            "normal activities (Teams, Outlook, OneDrive). User is accountEnabled=true unless "
            "the request is a PATCH/disable, in which case reflect the change."
        )

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
8. INDICATOR ECHO: any IP, hash, user, host, or domain mentioned in the request MUST
   reappear verbatim in the response somewhere (id field, name field, related record,
   src/dest field, etc.). Never substitute a different identifier than what was asked.
9. DATE WINDOW: every timestamp/date you emit must fall between 2025-01-01T00:00:00Z
   and the date provided in the user message ('today' field). Never emit 2023 or 2024 dates.
   Use ISO 8601 with timezone for full timestamps, YYYY-MM-DD for dates,
   and current-ish Unix epoch seconds for *_date fields (within the epoch range
   the user message provides — typically between EPOCH_LOWER and EPOCH_UPPER).
10. GENERIC ROOT (GET /): NEVER respond with a status/heartbeat document or service-name
    string. If the path is "/" or otherwise empty, return a vendor-shaped 404-style error
    envelope (e.g. {"error":{"code":"NotFound","message":"Resource not found"}}) or a
    vendor-default object — never "SOAR Integration Gateway" or similar self-identification.
11. NO META-LEAKAGE: never include the words "mock", "fake", "test", "synthetic", "SOAR
    integration gateway", "harness", or "placeholder" in any string value in the response.
    The output should look like real vendor JSON.

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

### GreyNoise  (/v3/community/, /v2/noise/, /v3/noise/, /v3/experimental/)
GET /v3/community/{ip}
  → {"ip": "{ip}", "noise": {true|false}, "riot": {true|false},
     "classification": "{malicious|benign|unknown}",
     "name": "{org or Tor Exit Node}", "last_seen": "{YYYY-MM-DD}",
     "link": "https://viz.greynoise.io/ip/{ip}",
     "message": "{one-sentence description}"}

GET /v2/noise/context/{ip}  or  GET /v3/noise/context/{ip}
  → {"ip": "{ip}", "seen": {bool}, "classification": "{classification}",
     "first_seen": "{date}", "last_seen": "{date}",
     "tags": ["{tag}", ...], "actor": "{actor or unknown}",
     "spoofable": false, "bot": {bool}, "vpn": {bool},
     "metadata": {"country": "{country}", "country_code": "{CC}",
       "city": "{city}", "organization": "{org}", "asn": "AS{number}"},
     "raw_data": {"scan": [{"port": {port}, "protocol": "TCP"}, ...]}}

GET /v3/experimental/gnql?query={gnql_expression}
  CRITICAL: return `data` array, NOT a single object.
  → {"data": [
       {"ip": "{ip}", "first_seen": "{YYYY-MM-DD}", "last_seen": "{YYYY-MM-DD}",
        "seen": true, "classification": "{malicious|benign|unknown}",
        "actor": "{actor or 'unknown'}", "spoofable": false,
        "bot": false, "vpn": false, "vpn_service": "",
        "tags": ["{tag1}", "{tag2}"],
        "cve": [],
        "metadata": {"asn": "AS{number}", "city": "{city}", "country": "{country}",
                     "country_code": "{2CC}", "organization": "{org}",
                     "category": "{isp|hosting|business}",
                     "rdns": "{reverse_dns_or_empty_string}"}
       },
       ... 4-8 distinct IP records ...
     ],
     "count": {N}, "complete": true, "message": "ok", "scroll": null}
  Return 4-8 IPs matching the query intent. If query contains "malicious", all records
  must have classification="malicious". Include diverse IPs from multiple countries.

### Recorded Future v2  (/v2/ip/, /v2/domain/, /v2/hash/, /v2/url/)
X-RFToken header authentication. CRITICAL: ALL responses MUST include the outer `data` key.
Workflows access `data.risk.score` — returning score at top level breaks workflow gating.

GET /v2/ip/{ip}?fields=...
GET /v2/domain/{domain}?fields=...
GET /v2/hash/{hash}?fields=...
GET /v2/url/{encoded_url}?fields=...
  → {"data": {
       "entity": {
         "id": "ip:{ip}|idn:{domain}|hash:{hash}|url:{url}",
         "name": "{the indicator}",
         "type": "IpAddress|InternetDomainName|Hash|URL"
       },
       "risk": {
         "score": {0-100},
         "rules": {N},
         "criticality": {0-3},
         "criticalityLabel": "None|Unusual|Suspicious|Malicious",
         "riskSummary": "{N} of 52 Risk Rules currently observed.",
         "evidenceDetails": [
           {"rule": "{rule_name}", "criticality": {0-3},
            "criticalityLabel": "{label}",
            "evidenceString": "{one-sentence evidence description}",
            "timestamp": "{ISO8601}"}
         ]
       },
       "timestamps": {
         "firstSeen": "{ISO8601}",
         "lastSeen": "{ISO8601}"
       },
       "intelCard": "https://app.recordedfuture.com/live/sc/entity/{type}%3A{encoded_indicator}",
       "relatedEntities": [
         {"type": "RelatedIpAddress", "count": {N},
          "entities": [{"id": "ip:{ip}", "name": "{ip}", "type": "IpAddress"}]},
         {"type": "RelatedHash", "count": {N},
          "entities": [{"id": "hash:{h}", "name": "{h}", "type": "Hash"}]},
         {"type": "InternetDomainName", "count": {N},
          "entities": [{"id": "idn:{d}", "name": "{d}", "type": "InternetDomainName"}]},
         {"type": "CyberVulnerability", "count": 0, "entities": []}
       ]
     }}
  For malicious indicators: score 75-99, criticalityLabel "Malicious", 3-5 evidenceDetails.
  For benign/clean: score 0-25, criticalityLabel "None" or "Unusual", 0-2 evidenceDetails.
  `relatedEntities` only included if "relatedEntities" appears in the `fields` query param.

### PassiveTotal / RiskIQ v2  (/v2/whois, /v2/enrichment)
Basic auth. CRITICAL: `organization` and `country` must be top-level fields in /v2/whois.
Do NOT return GreyNoise-shaped data for these paths.

GET /v2/whois?query={domain_or_ip}
  → {"domain": "{domain}", "organization": "{registrant_org}", "country": "{2CC}",
     "registrar": "{registrar_name}",
     "registered": "{ISO8601}", "expiresAt": "{ISO8601}", "lastLoadedAt": "{ISO8601}",
     "contactEmail": "{email}", "nameServers": ["{ns1}", "{ns2}"],
     "whoisServer": "whois.registrar.com",
     "registrant": {"organization": "{org}", "country": "{CC}", "email": "{email}"},
     "admin": {"organization": "{org}", "country": "{CC}"},
     "tech": {"organization": "{org}", "country": "{CC}"}}

GET /v2/enrichment?query={ip_or_domain}
  → {"queryValue": "{indicator}", "queryType": "domain|ip",
     "classification": "malicious|benign|suspicious|unknown",
     "sinkhole": false, "everCompromised": {bool},
     "tags": ["{tag}"],
     "primaryDomain": "{domain}", "subdomains": ["{sub}"],
     "lastSeen": "{ISO8601}", "firstSeen": "{ISO8601}",
     "autonomousSystemNumber": {asn}, "autonomousSystemName": "{org}",
     "network": "{CIDR}", "country": "{2CC}", "sslCertCount": {N}}

### Anomali ThreatStream v2  (/api/v2/intelligence/)
CRITICAL: Use `objects` array key, NOT `data`. Returning `data` instead of `objects` breaks callers.
NEVER return empty `objects: []` — always include 1-3 matching records.

GET /api/v2/intelligence/?type={ip|domain|md5|sha256|url|email}&value={indicator}
  → {"objects": [
       {"id": {int}, "type": "{ip|domain|md5|sha256|url|email}",
        "value": "{indicator}",
        "status": "active",
        "classification": "public",
        "confidence": {0-100},
        "threat_type": "c2|malware|phishing|spam|apt|unk",
        "source": "{source_name}",
        "severity": "very-high|high|medium|low",
        "country": "{2CC}", "asn": "AS{number}", "org": "{org_name}",
        "tlp": "green|white|amber",
        "itype": "mal_ip|c2_domain|malware_hash|phish_url|mal_email",
        "created_ts": "{ISO8601}", "modified_ts": "{ISO8601}",
        "expiration_ts": "{ISO8601}"}
     ],
     "meta": {"total_count": {N}, "limit": 20, "next": null, "offset": 0, "took": 0.234}}

### TruSTAR / Splunk Intelligence Management v1.3  (/api/1.3/)
CRITICAL: top-level `priorityScore` and `reportId` are mandatory.
Workflows gate on `output.priorityScore` and pivot to `output.reportId`.

POST /api/1.3/indicators/search
  → {"priorityScore": "CRITICAL|HIGH|MEDIUM|LOW|NOT_FOUND",
     "reportId": "{UUID-or-alphanumeric-id}",
     "indicators": [
       {"indicatorType": "IP|URL|MD5|SHA256|DOMAIN|EMAIL",
        "value": "{indicator}",
        "priorityScore": "CRITICAL|HIGH|MEDIUM|LOW",
        "reportIds": ["{reportId}"],
        "weight": {0-10}}
     ],
     "pageNumber": 0, "pageSize": 25, "hasNextPage": false}
  For malicious indicators: priorityScore "HIGH" or "CRITICAL".
  For benign indicators: priorityScore "LOW" or "NOT_FOUND".

GET /api/1.3/reports/{reportId}
  → {"id": "{reportId}", "title": "{incident_title}",
     "created": {unix_ms}, "updated": {unix_ms},
     "submittedUrl": null,
     "reportBody": "{narrative_with_IOCs}",
     "enclave_ids": ["{uuid}"], "distribution_type": "ENCLAVE"}

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

### URLScan.io  (/api/v1/scan/, /api/v1/result/)
POST /api/v1/scan/
  CRITICAL: return `uuid` (not scan_id) so the follow-up GET can reference it.
  → {"uuid": "{uuid}", "result": "https://urlscan.io/result/{uuid}/",
     "api": "https://urlscan.io/api/v1/result/{uuid}/",
     "visibility": "public", "options": {"useragent": "Mozilla/5.0 (automated)"}}

GET /api/v1/result/{uuid}
  → {"data": {"requests": [{...}], "console": []},
     "lists": {"ips": ["{ip}"], "countries": ["{CC}"], "domains": ["{domain}"]},
     "verdicts": {"overall": {"score": {0-100}, "categories": ["{category}"],
       "brands": [], "malicious": {bool}},
       "urlscan": {"score": {0-100}, "categories": ["{category}"],
         "malicious": {bool}}},
     "task": {"uuid": "{uuid}", "url": "{scanned_url}", "time": "{ISO8601}",
       "visibility": "public", "reportURL": "https://urlscan.io/result/{uuid}/"},
     "page": {"domain": "{domain}", "ip": "{resolved_ip}", "country": "{2CC}",
       "status": "200", "title": "{page_title}",
       "mimeType": "text/html", "tlsIssuer": "{cert_issuer}"}}
  For malicious URLs: verdicts.overall.malicious=true, score=80+, categories=["malware","c2"].
  For benign URLs: verdicts.overall.malicious=false, score=0-15.

### PhishTank / OpenPhish  (/checkurl/, /api/, /feed/)
POST or GET on phish-check endpoints
  → {"in_database": {true|false}, "phish_id": "{id or null}",
     "phish_detail_page": "{url or null}",
     "valid": {true|false}, "verified": {true|false},
     "verified_at": "{ISO8601 or null}",
     "target": "{brand name or null}"}
  If the URL/domain looks suspicious: in_database=true, valid=true, verified=true.
  If benign: in_database=false, valid=false.

### Cisco Umbrella Reporting API  (/1.0/events, /1.0/)
CRITICAL: return a JSON array (NOT a dict with `events` key).

GET /1.0/events?customerKey={key}&from={ts}&to={ts}
  → [
      {"externalIp": "{external_ip}", "internalIp": "{internal_ip}",
       "domain": "{queried_domain}",
       "deviceId": "{uuid}", "deviceVersion": "0.3.35",
       "timestamp": {unix_ms},
       "verdict": "blocked|allowed",
       "reason": "Malware|Phishing|Botnet|Custom|Newly Registered Domain",
       "actionTaken": "Blocked",
       "categories": [{"id": {N}, "label": "{category_name}", "type": "security"}],
       "type": "dns",
       "identityType": "ROAMING_COMPUTER",
       "identities": [{"id": {N}, "name": "{device_name}", "type": "Roaming Computers"}]
      }, ... 3-8 events
    ]
  Mix blocked/allowed events. For canonical domain/IP: verdict="blocked", reason="Malware".

### Gmail API  (/gmail/v1/users/)
GET /gmail/v1/users/{user}/messages?q={query}
  → {"messages": [{"id": "{hex16}", "threadId": "{hex16}"}], "resultSizeEstimate": {N}}

GET /gmail/v1/users/{user}/messages/{messageId}
  → {"id": "{messageId}", "threadId": "{threadId}",
     "labelIds": ["INBOX", "UNREAD"],
     "snippet": "{preview_first_100_chars}",
     "payload": {
       "headers": [
         {"name": "From", "value": "{sender_display} <{sender_email}>"},
         {"name": "To", "value": "{recipient_email}"},
         {"name": "Subject", "value": "{subject_line}"},
         {"name": "Date", "value": "{RFC2822_date}"},
         {"name": "Message-ID", "value": "{msg-id}"}
       ],
       "mimeType": "multipart/mixed",
       "parts": [{"mimeType": "text/plain",
                  "body": {"size": {N}, "data": "{base64_snippet}"}}]
     },
     "sizeEstimate": {N}, "internalDate": "{unix_ms_str}"}

POST /gmail/v1/users/{user}/messages/trash  or  .../modify
  → {"id": "{messageId}", "threadId": "{threadId}", "labelIds": ["TRASH"]}

### Google Workspace Admin SDK  (/admin/directory/v1/)
GET /admin/directory/v1/users/{userKey}
  → {"kind": "admin#directory#user", "id": "{numeric_id}", "etag": "{etag}",
     "primaryEmail": "{email}",
     "name": {"givenName": "{first}", "familyName": "{last}", "fullName": "{full}"},
     "isAdmin": false, "isDelegatedAdmin": false,
     "lastLoginTime": "{ISO8601}", "creationTime": "{ISO8601}",
     "suspended": false, "archived": false,
     "orgUnitPath": "/{department}",
     "includeInGlobalAddressList": true,
     "customerId": "C{8chars}",
     "emails": [{"address": "{email}", "primary": true}]}

POST /admin/directory/v1/users/{userKey}/signOut  → {} (200 OK empty body)

### AWS EC2  (path /ec2 or query Action=Describe*)
Action=DescribeInstances
  → {"DescribeInstancesResponse": {
       "reservationSet": [
         {"reservationId": "r-{hex}", "instancesSet": [
           {"instanceId": "i-{17hex}", "instanceType": "{t3.medium|m5.large|...}",
            "instanceState": {"code": 16, "name": "running"},
            "privateDnsName": "{hostname}.{region}.compute.internal",
            "privateIpAddress": "{private_ip}",
            "publicIpAddress": "{public_ip_or_absent}",
            "ipAddress": "{public_ip}",
            "tagSet": [{"key": "Name", "value": "{instance_name}"},
                       {"key": "Environment", "value": "production"}],
            "launchTime": "{ISO8601}",
            "placement": {"availabilityZone": "{region}a"},
            "platform": "windows|linux",
            "imageId": "ami-{8hex}"}
         ]}
       ],
       "ResponseMetadata": {"RequestId": "{uuid}"}}}

Action=DescribeSecurityGroups
  → {"DescribeSecurityGroupsResponse": {
       "securityGroupInfo": [
         {"groupId": "sg-{8hex}", "groupName": "{name}",
          "groupDescription": "{description}",
          "ipPermissions": [{"ipProtocol": "tcp", "fromPort": {N}, "toPort": {N},
                              "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}],
          "ipPermissionsEgress": [{"ipProtocol": "-1", "fromPort": -1, "toPort": -1,
                                    "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}
       ],
       "ResponseMetadata": {"RequestId": "{uuid}"}}}

### Google Cloud Compute  (/compute/v1/)
GET /compute/v1/projects/{project}/zones/{zone}/instances/{instance}
  → {"id": "{numeric}", "name": "{instance_name}", "zone": "zones/{zone}",
     "machineType": "zones/{zone}/machineTypes/n1-standard-2",
     "status": "RUNNING",
     "networkInterfaces": [{"name": "nic0", "networkIP": "{internal_ip}",
       "accessConfigs": [{"natIP": "{external_ip}"}]}],
     "disks": [{"source": "projects/{project}/zones/{zone}/disks/{disk_name}",
                "boot": true, "autoDelete": true}],
     "creationTimestamp": "{ISO8601}",
     "labels": {"environment": "production"}}

### MaxMind GeoIP v2.1  (/geoip/v2.1/)
GET /geoip/v2.1/city/{ip}
  → {"continent": {"code": "{2CC}", "geoname_id": {N},
       "names": {"en": "{continent_name}"}},
     "country": {"geoname_id": {N}, "iso_code": "{2CC}",
       "names": {"en": "{country_name}"}},
     "city": {"geoname_id": {N}, "names": {"en": "{city_name}"}},
     "postal": {"code": "{postal_code}"},
     "subdivisions": [{"iso_code": "{state_code}", "names": {"en": "{state_name}"}}],
     "location": {"accuracy_radius": {N}, "latitude": {float},
       "longitude": {float}, "time_zone": "{tz}"},
     "traits": {"ip_address": "{ip}", "network": "{CIDR}",
       "autonomous_system_number": {asn},
       "autonomous_system_organization": "{org}",
       "isp": "{isp_name}", "organization": "{org_name}"}}

### Google Safe Browsing v4  (/v4/threatMatches:find)
POST /v4/threatMatches:find
  → {"matches": [
       {"threatType": "MALWARE|SOCIAL_ENGINEERING|UNWANTED_SOFTWARE",
        "platformType": "ANY_PLATFORM",
        "threat": {"url": "{the_url}"},
        "cacheDuration": "300.000s",
        "threatEntryType": "URL",
        "threatEntryMetadata": {"entries": [
          {"key": "malware_threat_type", "value": "DISTRIBUTION|LANDING"}
        ]}}
     ]}
  If URL/domain is benign: return {} (empty matches).
  If URL/domain is malicious: return 1-2 matches.

### DomainTools / WhoisXML  (/whoisserver/WhoisService, /v2/whois)
POST /whoisserver/WhoisService?queryType=GET_WHOIS_RECORD&domainName={domain}
  → {"WhoisRecord": {
       "domainName": "{domain}", "domainNameExt": ".{tld}",
       "createdDate": "{ISO8601}", "updatedDate": "{ISO8601}", "expiresDate": "{ISO8601}",
       "registrarName": "{registrar}",
       "registrant": {"name": "{name_or_privacy}", "organization": "{org}",
                      "email": "{email_or_redacted}", "country": "{2CC}",
                      "countryCode": "{2CC}", "city": "{city}"},
       "nameServers": {"hostNames": ["{ns1}", "{ns2}"]},
       "status": "ACTIVE",
       "rawText": "{whois_text}"}}

### Generic / fallback
If the path doesn't match any vendor above: infer from URL structure and HTTP method,
return a plausible vendor-shaped JSON response. Never return {"data":[], "status":"ok"}.
"""

# ── AI assistant prompt (free-form text, not vendor JSON) ─────────────────────
# Used by POST /ai/invoke — returns {"output": "<markdown text>"}

AI_ASSIST_PROMPT = f"""You are a senior SOC analyst and incident responder writing a detailed security investigation report.
You are NOT acting as a vendor API. Write professional security analysis in markdown.

RULES:
1. Write in professional security analyst voice. Be specific and actionable.
2. Use the EXACT indicator values from the input — never write [IP], [hash], or any placeholder.
3. Use markdown: ## headers, markdown tables (| col | col |), and - bullet lists.
4. Base MITRE ATT&CK mappings on the actual techniques described in the input.
5. Attribution must name real threat actor/malware families when the evidence supports it.
6. Response playbook actions must reference the specific systems and accounts from the input.
7. ES|QL queries must be syntactically valid and embed the actual indicator values.
8. Dates must fall between 2025-01-01 and {TODAY}.

CANONICAL INCIDENT (use these facts when the request mentions jdoe@acmecorp.com,
185.220.101.47, DESKTOP-A4K9B2Z, invoice_march.exe, or evil.example.com):
- Phishing email arrived: {SCENARIO_START}
- CrowdStrike first detection: {SCENARIO_DETECTION}
- Malware name: invoice_march.exe  |  Family: TrickBot.Loader.Gen
- Threat actor: TA505 (Evil Corp affiliate) — confidence HIGH based on TrickBot + TOR C2 TTPs
- Kill chain: Spearphishing Attachment (T1566.001) → User Execution (T1204.002)
  → C2 over TOR (T1090.003) → Credential Dumping risk (T1003) → Exfiltration risk (T1041)
- C2 IP 185.220.101.47 is a TOR exit node in Berlin, AS208294 Zwiebelfreunde e.V.
- jdoe is an Accounts Payable Specialist — Finance dept — high-value target for BEC/fraud
- DESKTOP-A4K9B2Z had {SCENARIO_DETECTION} CrowdStrike detection, account still enabled as of triage
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

def _ai_assist_synth(method: str, path: str, query: str, body: bytes) -> dict:
    """Handle POST /ai/invoke — free-form markdown response wrapped in {"output": "..."}."""
    body_str = body.decode("utf-8", "replace") if body else ""
    try:
        message = json.loads(body_str).get("message", body_str)
    except Exception:
        message = body_str

    anchored = _request_touches_scenario(path, query, body_str)
    system_blocks = [{"text": AI_ASSIST_PROMPT}]
    if anchored:
        system_blocks.append({"text": SCENARIO_BLOCK})

    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=system_blocks,
        messages=[{"role": "user", "content": [{"text": message}]}],
        inferenceConfig={"maxTokens": 4096},
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()
    return {"output": text}


def synth(method: str, path: str, query: str, body: bytes) -> dict:
    # AI assistant proxy — free-form markdown, not vendor JSON
    if path.startswith("/ai/"):
        return _ai_assist_synth(method, path, query, body)

    body_str = body.decode("utf-8", "replace") if body else ""

    # For opaque async-style endpoints (Splunk jobs/{sid}/results, urlscan
    # /result/{id}, etc.) the path/body alone has no indicator. Look up the
    # original request that created the resource so the LLM can ground its
    # response.
    correlated = _correlate_request(method, path, body_str)
    effective_body_for_extraction = correlated.get("origin_body", body_str)
    effective_path_for_extraction = correlated.get("origin_path", path)

    indicator = _extract_indicator(effective_path_for_extraction, query, effective_body_for_extraction)
    assessment = _assess_indicator(indicator)
    anchored = _request_touches_scenario(effective_path_for_extraction, query, effective_body_for_extraction)

    origin_hint = ""
    if "origin_path" in correlated:
        origin_hint = (
            f"\nOriginating request that created this resource:\n"
            f"  origin path: {correlated['origin_path']}\n"
            f"  origin body: {correlated.get('origin_body','')[:1000]}\n"
        )

    user_msg = (
        f"HTTP request to mock:\n"
        f"  today:  {TODAY}\n"
        f"  epoch:  between {EPOCH_LOWER} and {EPOCH_UPPER} for *_date fields\n"
        f"  method: {method}\n"
        f"  path:   {path}\n"
        f"  query:  {query or '(none)'}\n"
        f"  body:   {body_str[:2000] or '(empty)'}\n"
        f"{origin_hint}"
        f"\nExtracted indicator: {indicator['type']} = {indicator['value']!r}\n"
        f"Reputation assessment: {assessment}\n"
        f"Anchored to canonical scenario: {anchored}\n\n"
        f"Return the complete JSON response body the vendor would send for this request."
    )

    system_blocks = [{"text": SYSTEM_PROMPT}]
    if anchored:
        system_blocks.append({"text": SCENARIO_BLOCK})

    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=system_blocks,
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


# ── Hardcoded handlers ───────────────────────────────────────────────────────
# Auth/Graph paths that must look real (JWT shape, 204 No Content, etc.) but
# don't depend on the indicator under test. Bypasses the LLM entirely.
#
# A handler returns (status_code: int, payload: dict | None). When payload is
# None the server emits an empty body (used for 204 No Content).

# Three-segment JWT to satisfy Azure "no dots" validator. Header/payload
# decode to standard {alg,typ}/{sub,aud,iat,exp} JSON. Signature is opaque.
_MOCK_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJtb2NrLXNvYXItaGFybmVzcyIsImF1ZCI6Im1vY2staXNzdWVyIiwiaWF0Ij"
    "oxNzE3MDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9"
    ".HMACSIGNATUREPLACEHOLDER0123456789abcdef"
)


def _oauth_token(method, path, query, body):
    return 200, {
        "access_token": _MOCK_JWT,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "*",
        "refresh_token": "refresh-mock-token",
    }


def _graph_patch_user(method, path, query, body):
    # MS Graph PATCH /v1.0/users/{id} returns 204 No Content on success.
    return 204, None


_CANONICAL_GRAPH_USERS = {
    CANONICAL["user"].lower(): {
        "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "displayName": CANONICAL["user_display"],
        "givenName": CANONICAL["user_display"].split(" ", 1)[0],
        "surname": CANONICAL["user_display"].split(" ", 1)[-1],
        "jobTitle": "Accounts Payable Specialist",
        "department": "Finance",
        "officeLocation": "HQ-3W",
        "accountEnabled": True,
    },
    CANONICAL["second_user"].lower(): {
        "id": "5a8c9e02-7b1d-4e3f-9876-fedcba012345",
        "displayName": CANONICAL["second_display"],
        "givenName": CANONICAL["second_display"].split(" ", 1)[0],
        "surname": CANONICAL["second_display"].split(" ", 1)[-1],
        "jobTitle": "Senior SOC Analyst",
        "department": "Security",
        "officeLocation": "HQ-2N",
        "accountEnabled": True,
    },
}


def _graph_get_user(method, path, query, body):
    # PATH /v1.0/users/{id}. If the id matches a canonical user, return their
    # real profile; otherwise reflect the id back with a synthesized display
    # name so the response still looks like a normal Graph entity (NOT the
    # raw email string as displayName, which is unconvincing).
    user_id = urllib.parse.unquote(path.rsplit("/", 1)[-1]) or "mock-user"
    canon = _CANONICAL_GRAPH_USERS.get(user_id.lower())
    if canon:
        upn = user_id if "@" in user_id else CANONICAL["user"]
        return 200, {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
            "id": canon["id"],
            "userPrincipalName": upn,
            "displayName": canon["displayName"],
            "givenName": canon["givenName"],
            "surname": canon["surname"],
            "jobTitle": canon["jobTitle"],
            "department": canon["department"],
            "officeLocation": canon["officeLocation"],
            "accountEnabled": canon["accountEnabled"],
            "mail": upn,
            "mobilePhone": None,
            "businessPhones": [],
            "preferredLanguage": "en-US",
        }
    # Non-canonical user: synthesize a plausible display name from the local
    # part of the email/UPN ("alice.smith" → "Alice Smith").
    local = user_id.split("@", 1)[0]
    display = " ".join(p.capitalize() for p in re.split(r"[._-]+", local) if p) or local
    upn = user_id if "@" in user_id else f"{user_id}@example.com"
    return 200, {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
        "id": user_id,
        "userPrincipalName": upn,
        "displayName": display,
        "accountEnabled": True,
        "mail": upn,
    }


def _graph_list_users(method, path, query, body):
    return 200, {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
        "value": [
            {"id": _CANONICAL_GRAPH_USERS[CANONICAL["user"].lower()]["id"],
             "userPrincipalName": CANONICAL["user"],
             "displayName": CANONICAL["user_display"],
             "givenName": "John", "surname": "Doe",
             "jobTitle": "Accounts Payable Specialist", "department": "Finance",
             "accountEnabled": True,
             "mail": CANONICAL["user"]},
            {"id": _CANONICAL_GRAPH_USERS[CANONICAL["second_user"].lower()]["id"],
             "userPrincipalName": CANONICAL["second_user"],
             "displayName": CANONICAL["second_display"],
             "givenName": "Jane", "surname": "Analyst",
             "jobTitle": "Senior SOC Analyst", "department": "Security",
             "accountEnabled": True,
             "mail": CANONICAL["second_user"]},
        ],
    }


def _defender_machine_action(method, path, query, body):
    # /api/machines/{id}/isolate or /unisolate → 201 Created with a tracking object
    machine_id = re.search(r"/machines/([^/]+)", path)
    return 201, {
        "@odata.context": "https://api.security.microsoft.com/api/$metadata#MachineActions/$entity",
        "id": "00000000-mock-isolate-action",
        "type": "Isolate" if "isolate" in path.lower() else "Unisolate",
        "scope": "Selective",
        "machineId": machine_id.group(1) if machine_id else "mock-machine",
        "status": "Pending",
        "creationDateTime": "2026-06-03T13:00:00Z",
    }


# Pattern → handler. Patterns are anchored regex matched against the URL path.
# Tried in order; first match wins.
HARDCODED_HANDLERS = [
    # CrowdStrike OAuth token endpoint
    (re.compile(r"^/oauth2/token$"),                       ("POST",),     _oauth_token),
    # Azure AD multi-tenant token endpoints — tenant id (or "common"/"organizations") before the path
    (re.compile(r"^/[^/]+/oauth2/(v2\.0/)?token$"),        ("POST",),     _oauth_token),
    # Microsoft Graph user PATCH (disable/enable) and GET
    (re.compile(r"^/v1\.0/users/[^/]+$"),                  ("PATCH",),    _graph_patch_user),
    (re.compile(r"^/v1\.0/users/[^/]+$"),                  ("GET",),      _graph_get_user),
    (re.compile(r"^/v1\.0/users/?$"),                      ("GET",),      _graph_list_users),
    # Microsoft Defender for Endpoint machine actions
    (re.compile(r"^/api/machines/[^/]+/(isolate|unisolate)$"),
                                                            ("POST",),     _defender_machine_action),
]


def _try_hardcoded(method: str, path: str, query: str, body: bytes):
    for pat, methods, fn in HARDCODED_HANDLERS:
        if method in methods and pat.match(path):
            return fn(method, path, query, body)
    return None


# ── HTTP server ───────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def _serve(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""

        # Hardcoded paths (auth, MS Graph) — bypass LLM and cache.
        hc = _try_hardcoded(method, parsed.path, parsed.query, body)
        if hc is not None:
            status_code, payload = hc
            if payload is None:
                self.send_response(status_code)
                self.send_header("Content-Length", "0")
                self.send_header("X-Mock-Source", "hardcoded")
                self.end_headers()
                sys.stderr.write(f"[hardcd] {method} {parsed.path} -> {status_code} (no body)\n")
                return
            out = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.send_header("X-Mock-Source", "hardcoded")
            self.end_headers()
            self.wfile.write(out)
            sys.stderr.write(f"[hardcd] {method} {parsed.path} -> {status_code} {len(out)}B\n")
            return

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

        body_str_for_trace = body.decode("utf-8", "replace") if body else ""
        _trace_creation(method, parsed.path, body_str_for_trace, payload)

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
