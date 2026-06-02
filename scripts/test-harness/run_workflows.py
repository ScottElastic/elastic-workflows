#!/usr/bin/env python3
"""
Triggers every imported workflow with a canned input payload and reports
pass/fail. Pairs with import_workflows.py — reads its imported.json
output mapping.

Usage:
    export KIBANA_URL="https://YOUR-DEPLOY.kb.REGION.PROVIDER.elastic-cloud.com"
    export KIBANA_API_KEY="<base64 id:api_key>"
    python3 run_workflows.py [--mapping imported.json] [--space default] [--out results.json]

Each workflow gets a generic input bundle (user, ip, url, hash, domain,
case_id, etc.). Most workflows ignore inputs they don't declare and Use
defaults; the rest will pull what they need from this bundle.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path


_MALICIOUS_IP = "185.220.101.47"
_HOSTNAME = "DESKTOP-A4K9B2Z"
_USER = "jdoe@acmecorp.com"
_SHA256 = "a3f8e2d1c9b4f7e6a5d2c8b1e9f4a7d3c6b2e5f8a1d4c7b3e6f2a9d5c8b4e7f1"
_MSG_ID = "<4d2a9f3b@mail.acmecorp.com>"

CANNED_INPUTS = {
    # Identity
    "user": _USER,
    "users": [_USER, "janalyst@acmecorp.com"],
    "launching_user": _USER,
    "closing_user": "janalyst@acmecorp.com",
    # Network
    "ip": _MALICIOUS_IP,
    "ips": [_MALICIOUS_IP, "198.51.100.10"],
    "client_ip": "10.10.14.22",
    "server_ip": _MALICIOUS_IP,
    "source_address": _MALICIOUS_IP,
    "destination_address": _MALICIOUS_IP,
    "destination_dns_domain": "evil.example.com",
    "dns_query": "evil.example.com",
    "dns_uid": "C4tQnq2KS5MfzZuZl9",
    "id_orig_h": "10.10.14.22",
    # Host
    "hostname": _HOSTNAME,
    "ip_or_hostname": [_HOSTNAME],
    "ip_or_hostname_str": _HOSTNAME,
    "device_id": "a3f8e2d14c9b4f7e",
    "machine_id": "a3f8e2d14c9b4f7e",
    "is_virtual": False,
    "vmx_path": "[datastore1] vm/desktop-a4k9b2z.vmx",
    # URLs
    "url": "https://185.220.101.47/dropper/stage2.ps1",
    "urls": ["https://185.220.101.47/dropper/stage2.ps1"],
    "request_url": "https://185.220.101.47/dropper/stage2.ps1",
    "source_url": "https://185.220.101.47/dropper/stage2.ps1",
    # Domain
    "domain": "evil.example.com",
    "domains": ["evil.example.com", "185.220.101.47"],
    # File hashes
    "hash": _SHA256,
    "hashes": [_SHA256],
    "file_hash_md5": "a3f8e2d14c9b4f7e",
    "file_hash_sha1": "a3f8e2d14c9b4f7ea5d2c8b1",
    "file_hash_sha256": _SHA256,
    "source_data_identifier": _SHA256,
    # Email
    "internet_message_id": _MSG_ID,
    "network_message_id": "4d2a9f3b1748899200",
    "message_id": [_MSG_ID],
    "email": [_USER, "janalyst@acmecorp.com"],
    "raw_email_body": (
        "From: hr-noreply@acmecorp-invoices.com\r\n"
        "To: jdoe@acmecorp.com\r\n"
        f"Message-ID: {_MSG_ID}\r\n"
        "Subject: ACTION REQUIRED: March Invoice\r\n"
        "Date: Mon, 02 Jun 2026 08:55:00 +0000\r\n\r\n"
        "Please review the attached invoice and confirm receipt.\r\n"
        "Download: https://185.220.101.47/dropper/invoice_march.exe\r\n"
    ),
    # SOAR / Splunk-ES fields
    "container_id": "12047",
    "container_name": "Phishing Alert — Malware Detected on DESKTOP-A4K9B2Z",
    "event_id": "EVT-2026-047821",
    "event_timestamp": "2026-06-02T09:32:00Z",
    "info_min_time": "2026-06-01T00:00:00Z",
    "info_max_time": "2026-06-02T23:59:59Z",
    "risk_object": _HOSTNAME,
    "risk_object_type": "system",
    "rule_name": "Suspicious Outbound Connection to Known TOR Exit Node",
    "source_data_identifier": _SHA256,
    "entity": _HOSTNAME,
    "uid": "C4tQnq2KS5MfzZuZl9",
    # Ticket / case fields
    "kibana_case_id": "",
    "case_id": "CASE-2026-0042",
    "snow_incident": "INC0047821",
    "ticket_title": "Investigate TOR exit node connection from DESKTOP-A4K9B2Z",
    "ticket_description": (
        f"CrowdStrike detected invoice_march.exe ({_SHA256[:16]}...) on {_HOSTNAME}. "
        f"Outbound connection to {_MALICIOUS_IP} (TOR). User {_USER} reported phishing email."
    ),
    "title": "Investigate TOR exit node connection from DESKTOP-A4K9B2Z",
    "description": "Automated investigation triggered by CrowdStrike detection.",
    "comment": "Confirmed malicious. Host isolated, user account suspended pending review.",
    "note": "Malware confirmed via VirusTotal (58/74 detections). Escalating to Tier 2.",
    "label": "malware",
    # Timing
    "close_time": "2026-06-02T18:00:00Z",
    "lookback_days": 7,
    "max_results": 50,
    # ServiceNow / workflow fields
    "isolation_type": "full",
    "nessus_policy_name": "Host Discovery",
    "threat_category": "malware",
    "alert_name": "Malware: Invoice Trojan Downloader",
    "dvc_ip": "10.10.14.22",
    # Booleans / flags
    "approve": False,
    "auto_approve": True,
    "dry_run": True,
    "response_choice": "",
    # Arrays
    "artifact_ids_include": [],
    "indicator_tags_exclude": [],
    "indicator_tags_include": ["malware", "apt", "tor"],
    "indicator_types_exclude": [],
    "indicator_types_include": ["ip", "domain", "hash"],
    "indicators": [
        {"cef_value": _MALICIOUS_IP, "data_types": ["ip"], "type": "ip", "value": _MALICIOUS_IP},
        {"cef_value": _SHA256, "data_types": ["hash"], "type": "hash", "value": _SHA256},
    ],
    "playbook_repo": [],
    "playbook_tags": ["malware", "endpoint", "phishing"],
    "responses": [],
}


def trigger(base_url: str, space: str, api_key: str, wf_id: str, inputs: dict):
    path = f"/s/{space}/api/workflows/workflow/{wf_id}/run" if space and space != "default" else f"/api/workflows/workflow/{wf_id}/run"
    req = urllib.request.Request(
        url=base_url.rstrip("/") + path,
        method="POST",
        headers={
            "kbn-xsrf": "true",
            "x-elastic-internal-origin": "Kibana",
            "Content-Type": "application/json",
            "Authorization": f"ApiKey {api_key}",
        },
        data=json.dumps({"inputs": inputs}).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")[:500]}
    except Exception as e:
        return 0, {"error": str(e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mapping", default="imported.json")
    ap.add_argument("--space", default="default")
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--filter", default="", help="Only run workflows whose YAML path contains this substring")
    ap.add_argument("--sleep", type=float, default=0.2, help="Sleep between calls to be kind to Kibana")
    args = ap.parse_args()

    base = os.environ.get("KIBANA_URL")
    key = os.environ.get("KIBANA_API_KEY")
    if not base or not key:
        sys.stderr.write("Set KIBANA_URL and KIBANA_API_KEY env vars.\n")
        return 2

    mapping = json.loads(Path(args.mapping).read_text())
    targets = [(p, info["id"]) for p, info in mapping.items() if info.get("id") and (args.filter in p)]

    results = {}
    ok = 0
    fail = 0
    for path, wf_id in targets:
        status, body = trigger(base, args.space, key, wf_id, CANNED_INPUTS)
        if 200 <= status < 300:
            run_status = body.get("status") or body.get("data", {}).get("status") or "completed"
            print(f"ok    {path}  →  {run_status}")
            results[path] = {"status": status, "result": body}
            ok += 1
        else:
            err = body.get("error") if isinstance(body, dict) else body
            print(f"FAIL  {path}  ({status})  {str(err)[:200]}")
            results[path] = {"status": status, "error": err}
            fail += 1
        time.sleep(args.sleep)

    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\n{ok}/{ok + fail} workflows completed (HTTP 2xx). Results in {args.out}.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
