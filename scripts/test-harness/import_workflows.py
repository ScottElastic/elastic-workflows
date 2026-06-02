#!/usr/bin/env python3
"""
Bulk-imports every workflow YAML in a directory into a Kibana space via
the Workflows API. Captures the assigned workflow id so the run script
can trigger each one later.

Usage:
    export KIBANA_URL="https://YOUR-DEPLOY.kb.REGION.PROVIDER.elastic-cloud.com"
    export KIBANA_API_KEY="<base64 id:api_key>"
    python3 import_workflows.py [--dir workflows/splunk-soar] [--space default] [--out imported.json]

The output file maps source YAML path → assigned Kibana workflow id.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path


def post_workflow(base_url: str, space: str, api_key: str, yaml_text: str):
    path = f"/s/{space}/api/workflows" if space and space != "default" else "/api/workflows"
    req = urllib.request.Request(
        url=base_url.rstrip("/") + path,
        method="POST",
        headers={
            "kbn-xsrf": "true",
            "x-elastic-internal-origin": "Kibana",
            "Content-Type": "application/json",
            "Authorization": f"ApiKey {api_key}",
        },
        data=json.dumps({"workflows": [{"yaml": yaml_text}]}).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")}
    except Exception as e:
        return 0, {"error": str(e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="workflows/splunk-soar")
    ap.add_argument("--space", default="default")
    ap.add_argument("--out", default="imported.json")
    ap.add_argument("--limit", type=int, default=0, help="0 = no limit")
    args = ap.parse_args()

    base = os.environ.get("KIBANA_URL")
    key = os.environ.get("KIBANA_API_KEY")
    if not base or not key:
        sys.stderr.write("Set KIBANA_URL and KIBANA_API_KEY env vars.\n")
        return 2

    files = sorted(Path(args.dir).rglob("*.yaml"))
    if args.limit:
        files = files[:args.limit]

    results = {}
    ok = 0
    fail = 0
    for f in files:
        yaml_text = f.read_text()
        status, body = post_workflow(base, args.space, key, yaml_text)
        if 200 <= status < 300:
            created = body.get("created", []) if isinstance(body, dict) else []
            first = created[0] if created else (body if isinstance(body, dict) else {})
            wf_id = first.get("id") or first.get("workflow_id")
            print(f"ok    {f}  →  {wf_id}")
            results[str(f)] = {"status": status, "id": wf_id}
            ok += 1
        else:
            err = body.get("error") if isinstance(body, dict) else body
            print(f"FAIL  {f}  ({status})  {str(err)[:200]}")
            results[str(f)] = {"status": status, "error": err}
            fail += 1

    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\n{ok} imported, {fail} failed. Mapping written to {args.out}.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
