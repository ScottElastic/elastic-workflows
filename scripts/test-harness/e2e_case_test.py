#!/usr/bin/env python3
"""
End-to-end case creation test for all Kibana Workflows.

Strategy:
  1. Snapshot existing case IDs before the run
  2. Trigger all workflows with AcmeCorp IOC inputs
  3. Wait for all executions to reach terminal state
  4. Fetch all Security cases; diff vs snapshot to find NEW ones
  5. Match new cases to their workflow by title ("Workflow: <name>")
  6. Verify per-case: owner, title, description, severity, status

Usage:
    export KIBANA_URL="https://YOUR-DEPLOY.kb.REGION.PROVIDER.elastic-cloud.com"
    export KIBANA_API_KEY="<base64 id:api_key>"
    python3 e2e_case_test.py [--mapping imported.json] [--out e2e_results.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

import run_workflows  # shares CANNED_INPUTS + build_inputs

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
KIBANA_API_KEY = os.environ.get("KIBANA_API_KEY", "")
TERMINAL = {"completed", "failed", "cancelled", "skipped", "timed_out"}


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _req(method: str, path: str, body: dict | None = None, timeout: int = 30):
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "kbn-xsrf": "true",
        "x-elastic-internal-origin": "Kibana",
        "Authorization": f"ApiKey {KIBANA_API_KEY}",
    }
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url=KIBANA_URL + path, method=method, headers=headers, data=data
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")[:800]}
    except Exception as e:
        return 0, {"error": str(e)}


# ── Cases API ─────────────────────────────────────────────────────────────────

def fetch_all_security_cases(owner: str = "securitySolution") -> dict[str, dict]:
    """Return {case_id: case_dict} for all cases in the space."""
    result: dict[str, dict] = {}
    page = 1
    per_page = 100
    while True:
        status, body = _req("GET", f"/api/cases/_find?owner={owner}&perPage={per_page}&page={page}")
        if status >= 400 or not isinstance(body, dict):
            break
        cases = body.get("cases", [])
        for c in cases:
            result[c["id"]] = c
        if len(cases) < per_page:
            break
        page += 1
    return result


# ── Workflow helpers ──────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).parent.parent.parent  # scripts/test-harness → repo root


def workflow_name_from_yaml(yaml_path: str) -> str:
    # Try the path as-is, then relative to repo root
    for candidate in [Path(yaml_path), _REPO_ROOT / yaml_path]:
        if candidate.exists():
            try:
                text = candidate.read_text()
                break
            except OSError:
                pass
    else:
        return Path(yaml_path).stem
    for line in text.split("\n"):
        m = re.match(r'^name:\s*["\']?(.*?)["\']?\s*$', line)
        if m:
            name = m.group(1).strip().strip("\"'")
            # Use same emoji-strip logic as add_case_creation.py
            name = re.sub(r'[\U00010000-\U0010ffff]', '', name)
            name = re.sub(r'[\U0001F300-\U0001F9FF]', '', name)
            name = name.strip()
            return name
    return Path(yaml_path).stem


def trigger_workflow(wf_id: str, inputs: dict):
    return _req("POST", f"/api/workflows/workflow/{wf_id}/run", {"inputs": inputs}, timeout=60)


def poll_execution(exec_id: str, max_wait: int = 90, interval: float = 3.0):
    deadline = time.time() + max_wait
    last = None
    while time.time() < deadline:
        status, body = _req("GET", f"/api/workflows/executions/{exec_id}")
        if status >= 400 or not isinstance(body, dict):
            return None, f"HTTP {status}"
        last = body
        if (body.get("status") or "").lower() in TERMINAL:
            return body, None
        time.sleep(interval)
    return last, "timed out"


def verify_case(case: dict) -> tuple[bool, list[str]]:
    issues = []
    if case.get("owner") != "securitySolution":
        issues.append(f"owner={case.get('owner')!r}")
    if not case.get("title"):
        issues.append("empty title")
    desc = case.get("description", "")
    if len(desc) < 20:
        issues.append(f"description too short ({len(desc)} chars)")
    if not case.get("severity"):
        issues.append("no severity")
    return len(issues) == 0, issues


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mapping", default="imported.json")
    ap.add_argument("--out", default="e2e_results.json")
    ap.add_argument("--filter", default="")
    ap.add_argument("--max-wait", type=int, default=90)
    ap.add_argument("--settle", type=int, default=5, help="Seconds to wait after all executions before fetching cases")
    ap.add_argument("--sleep", type=float, default=0.25)
    args = ap.parse_args()

    if not KIBANA_URL or not KIBANA_API_KEY:
        sys.stderr.write("Set KIBANA_URL and KIBANA_API_KEY.\n")
        return 2

    mapping = json.loads(Path(args.mapping).read_text())
    targets = [
        (p, info["id"]) for p, info in mapping.items()
        if info.get("id") and args.filter in p
    ]

    # Print IOC summary
    print(f"\n{'='*68}")
    print(f"TEST IOC INPUTS  (applied to all {len(targets)} workflows)")
    print(f"{'='*68}")
    print(f"  ip:        {run_workflows._MALICIOUS_IP}")
    print(f"  user:      {run_workflows._USER}")
    print(f"  hostname:  {run_workflows._HOSTNAME}")
    print(f"  sha256:    {run_workflows._SHA256[:32]}...")
    print(f"  domain:    evil.example.com")
    print(f"  url:       https://{run_workflows._MALICIOUS_IP}/dropper/stage2.ps1")
    print(f"  email_subj: ACTION REQUIRED: March Invoice")
    print(f"  from_email: hr-noreply@acmecorp-invoices.com")
    print(f"{'='*68}\n")

    # ── Phase 0: snapshot existing case IDs ──────────────────────────────────
    print("[Phase 0] Snapshotting existing Security cases...")
    existing_cases = fetch_all_security_cases()
    existing_ids = set(existing_cases.keys())
    print(f"  {len(existing_ids)} existing cases recorded\n")

    # ── Phase 1: trigger all workflows ───────────────────────────────────────
    run_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[Phase 1] Triggering {len(targets)} workflows ({run_start})...")

    exec_map: dict[str, str] = {}     # yaml_path → exec_id
    trigger_failures: dict[str, str] = {}

    for idx, (yaml_path, wf_id) in enumerate(targets, 1):
        inputs = run_workflows.build_inputs(yaml_path)
        status, body = trigger_workflow(wf_id, inputs)
        if 200 <= status < 300:
            exec_id = body.get("workflowExecutionId", "")
            exec_map[yaml_path] = exec_id
        else:
            err = (body.get("error") or str(body))[:120]
            trigger_failures[yaml_path] = f"HTTP {status}: {err}"
            print(f"  TRIGGER_FAIL [{idx}] {Path(yaml_path).stem}: {err}")
        if idx % 50 == 0 or idx == len(targets):
            print(f"  {idx}/{len(targets)} triggered...")
        time.sleep(args.sleep)

    print(f"  {len(exec_map)} triggered, {len(trigger_failures)} failed\n")

    # ── Phase 2: poll all executions ─────────────────────────────────────────
    print(f"[Phase 2] Polling {len(exec_map)} executions...")

    exec_results: dict[str, dict] = {}
    for idx, (yaml_path, exec_id) in enumerate(exec_map.items(), 1):
        if not exec_id:
            exec_results[yaml_path] = {"status": "no_exec_id"}
            continue
        exec_body, err = poll_execution(exec_id, max_wait=args.max_wait)
        exec_status = (exec_body or {}).get("status", "unknown")
        step_count = len((exec_body or {}).get("stepExecutions", []))
        exec_results[yaml_path] = {
            "exec_id": exec_id,
            "status": exec_status,
            "error": err,
            "steps": step_count,
        }
        if idx % 50 == 0 or idx == len(exec_map):
            completed = sum(1 for r in exec_results.values() if r.get("status") == "completed")
            failed = sum(1 for r in exec_results.values() if r.get("status") == "failed")
            print(f"  {idx}/{len(exec_map)} polled  (completed={completed} failed={failed})")

    completed_count = sum(1 for r in exec_results.values() if r.get("status") == "completed")
    failed_count = sum(1 for r in exec_results.values() if r.get("status") == "failed")
    other_count = len(exec_results) - completed_count - failed_count
    print(f"  Summary: {completed_count} completed, {failed_count} failed, {other_count} other\n")

    # ── Phase 3: diff cases ───────────────────────────────────────────────────
    print(f"[Phase 3] Waiting {args.settle}s for Kibana to index new cases...")
    time.sleep(args.settle)

    print(f"[Phase 3] Fetching all current Security cases...")
    current_cases = fetch_all_security_cases()
    new_case_ids = set(current_cases.keys()) - existing_ids
    new_cases = {cid: current_cases[cid] for cid in new_case_ids}
    print(f"  {len(new_cases)} new cases created by this test run\n")

    # Build lookup: title → case (newest per title)
    case_by_title: dict[str, dict] = {}
    for c in sorted(new_cases.values(), key=lambda x: x.get("created_at", "")):
        case_by_title[c.get("title", "")] = c

    # ── Phase 4: match + verify ───────────────────────────────────────────────
    print(f"[Phase 4] Matching {len(new_cases)} new cases to {len(targets)} workflows...\n")

    results = {}
    counts = {"ok": 0, "case_fail": 0, "no_case": 0, "exec_fail": 0, "trigger_fail": 0}

    for yaml_path, wf_id in targets:
        wf_name = workflow_name_from_yaml(yaml_path)
        stem = Path(yaml_path).stem

        if yaml_path in trigger_failures:
            counts["trigger_fail"] += 1
            results[yaml_path] = {"result": "trigger_fail", "error": trigger_failures[yaml_path]}
            continue

        exec_info = exec_results.get(yaml_path, {})
        exec_status = exec_info.get("status", "unknown")
        exec_id = exec_info.get("exec_id", "")

        expected_title = f"Workflow: {wf_name}"
        case = case_by_title.get(expected_title)

        if not case:
            if exec_status == "failed":
                counts["exec_fail"] += 1
                results[yaml_path] = {"result": "exec_fail", "exec_id": exec_id}
            else:
                counts["no_case"] += 1
                results[yaml_path] = {
                    "result": "no_case",
                    "exec_status": exec_status,
                    "exec_id": exec_id,
                    "expected_title": expected_title,
                }
                print(f"  NO_CASE  {stem}  exec={exec_status}")
            continue

        passed, issues = verify_case(case)
        case_id = case.get("id", "")
        case_url = f"{KIBANA_URL}/app/security/cases/{case_id}"

        if passed:
            counts["ok"] += 1
            results[yaml_path] = {
                "result": "ok",
                "exec_id": exec_id,
                "exec_status": exec_status,
                "case_id": case_id,
                "case_title": case.get("title"),
                "case_owner": case.get("owner"),
                "case_severity": case.get("severity"),
                "case_status": case.get("status"),
                "case_description_chars": len(case.get("description", "")),
                "case_url": case_url,
            }
        else:
            counts["case_fail"] += 1
            results[yaml_path] = {
                "result": "case_fail",
                "exec_id": exec_id,
                "case_id": case_id,
                "issues": issues,
                "case_title": case.get("title"),
            }
            print(f"  CASE_FAIL  {stem}  issues={issues}")

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(targets)
    ok_results = [(p, r) for p, r in results.items() if r.get("result") == "ok"]

    print(f"\n{'='*68}")
    print(f"END-TO-END RESULTS  ({datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})")
    print(f"{'='*68}")
    print(f"  IOC tested:")
    print(f"    ip={run_workflows._MALICIOUS_IP}  user={run_workflows._USER}")
    print(f"    host={run_workflows._HOSTNAME}  domain=evil.example.com")
    print(f"{'─'*68}")
    print(f"  Case created + verified (owner/title/desc OK):  {counts['ok']:>4} / {total}")
    print(f"  Case created but verify failed:                  {counts['case_fail']:>4}")
    print(f"  Execution completed, no matching case found:     {counts['no_case']:>4}")
    print(f"  Execution failed before reaching case step:      {counts['exec_fail']:>4}")
    print(f"  Trigger failed (HTTP error):                     {counts['trigger_fail']:>4}")
    print(f"{'='*68}")

    if ok_results:
        print(f"\nVerified cases ({len(ok_results)} total). Sample — first 15:")
        for _, r in ok_results[:15]:
            desc_len = r['case_description_chars']
            print(f"  [{r['case_severity']:6}] {r['case_title'][:62]}  ({desc_len}ch)")
            print(f"           {r['case_url']}")

    if counts["no_case"] > 0 or counts["case_fail"] > 0:
        print(f"\nWorkflows with no case or failed verification:")
        for path, r in results.items():
            if r.get("result") in ("no_case", "case_fail"):
                stem = Path(path).stem
                detail = r.get("issues") or r.get("expected_title", "")
                print(f"  [{r['result']}] {stem}: {detail}")

    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nFull results → {args.out}")
    print(f"Security Cases UI: {KIBANA_URL}/app/security/cases")
    return 0 if counts["ok"] == total else 1


if __name__ == "__main__":
    sys.exit(main())
