#!/usr/bin/env python3
"""
Polls each workflowExecutionId from a triggers_*.json file and records the
real completion status. Pairs with run_workflows.py (which only captures the
trigger acceptance).

Usage:
    export KIBANA_URL=...
    export KIBANA_API_KEY=...
    python3 poll_executions.py --in /tmp/soar-fetch/triggers_v7.json \
                               --out /tmp/soar-fetch/results_v7.json
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


def fetch(base: str, space: str, key: str, exec_id: str):
    path = (
        f"/s/{space}/api/workflows/executions/{exec_id}"
        if space and space != "default"
        else f"/api/workflows/executions/{exec_id}"
    )
    req = urllib.request.Request(
        url=base.rstrip("/") + path,
        method="GET",
        headers={
            "kbn-xsrf": "true",
            "x-elastic-internal-origin": "Kibana",
            "Authorization": f"ApiKey {key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")[:500]}
    except Exception as e:
        return 0, {"error": str(e)}


TERMINAL = {"completed", "failed", "cancelled", "skipped", "timed_out"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--space", default="default")
    ap.add_argument("--max-wait", type=int, default=180, help="Seconds to wait per execution to reach terminal status")
    ap.add_argument("--poll-interval", type=float, default=3.0)
    args = ap.parse_args()

    base = os.environ.get("KIBANA_URL")
    key = os.environ.get("KIBANA_API_KEY")
    if not base or not key:
        sys.stderr.write("Set KIBANA_URL and KIBANA_API_KEY env vars.\n")
        return 2

    triggers = json.loads(Path(args.inp).read_text())

    results = {}
    counts = {"completed": 0, "failed": 0, "other": 0, "no_exec_id": 0, "import_failed": 0}
    total = len(triggers)
    for idx, (path, info) in enumerate(triggers.items(), 1):
        if info.get("status") != 200:
            # workflow was rejected at run-trigger time (e.g., 400 import_failed earlier)
            results[path] = {"phase": "trigger", "status": info.get("status"), "error": info.get("error")}
            counts["import_failed"] += 1
            print(f"[{idx}/{total}] SKIP  {path}  trigger HTTP {info.get('status')}")
            continue

        exec_id = (info.get("result") or {}).get("workflowExecutionId")
        if not exec_id:
            results[path] = {"phase": "trigger", "error": "no execution id"}
            counts["no_exec_id"] += 1
            print(f"[{idx}/{total}] SKIP  {path}  no exec id")
            continue

        deadline = time.time() + args.max_wait
        last = None
        while time.time() < deadline:
            status, body = fetch(base, args.space, key, exec_id)
            if status >= 400 or not isinstance(body, dict):
                last = {"http": status, "body": body}
                break
            last = body
            wf_status = (body.get("status") or "").lower()
            if wf_status in TERMINAL:
                break
            time.sleep(args.poll_interval)

        wf_status = ((last or {}).get("status") or "").lower() if isinstance(last, dict) else ""
        if wf_status == "completed":
            counts["completed"] += 1
            print(f"[{idx}/{total}] PASS  {path}  ({exec_id[:8]})")
        elif wf_status in {"failed", "cancelled", "timed_out"}:
            counts["failed"] += 1
            err = (last.get("error") or {}).get("message") if isinstance(last.get("error"), dict) else last.get("error")
            print(f"[{idx}/{total}] FAIL  {path}  status={wf_status}  err={str(err)[:160]}")
        else:
            counts["other"] += 1
            print(f"[{idx}/{total}] ????  {path}  status={wf_status or 'n/a'}")

        results[path] = {
            "phase": "execution",
            "executionId": exec_id,
            "status": wf_status,
            "detail": last,
        }

    Path(args.out).write_text(json.dumps(results, indent=2))
    print("\n=== Summary ===")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    print(f"  total triggers: {total}")
    print(f"\nResults written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
