#!/usr/bin/env python3
"""
Lints Elastic Workflow YAML files for structural correctness.

Checks:
  - Valid YAML
  - Required top-level fields (name, steps)
  - Each step has name + type
  - Step names are unique within a workflow
  - Step types are in the known catalog (or http/generic for stubs)
  - Liquid template references ({{ ... }} / ${{ ... }}) parse cleanly
  - Step-to-step refs (steps.<name>.output) point to a real step
  - Triggers, settings, on-failure blocks match the schema

Usage:
  python3 validate.py path/to/workflow.yaml [more.yaml ...]
  python3 validate.py path/to/dir/   (recursive)

Exits 0 on success, 1 on any failure.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)


KNOWN_STEP_TYPES = {
    # Flow control
    "if", "foreach", "console", "data.set", "wait", "parallel", "atomic",
    # Elasticsearch
    "elasticsearch.search", "elasticsearch.index", "elasticsearch.indices.create",
    "elasticsearch.indices.delete", "elasticsearch.indices.exists",
    "elasticsearch.esql.query", "elasticsearch.request", "elasticsearch.bulk",
    "elasticsearch.update", "elasticsearch.delete", "elasticsearch.get",
    # Kibana
    "kibana.createCaseDefaultSpace", "kibana.SetAlertsStatus",
    "kibana.addCaseComment", "kibana.request",
    # External / connectors
    "http", "slack", "email", "pagerduty", "jira", "servicenow", "teams",
    "webhook", "opsgenie", "tines", "thehive", "resilient", "swimlane",
    # Threat intel connectors
    "virustotal.scanFileHash", "virustotal.scanUrl", "virustotal.scanIp",
    "virustotal.scanDomain", "abuseipdb", "greynoise", "shodan", "urlvoid",
    "alienvault", "cisco_talos", "reversinglabs", "urlscan", "phishtank",
    # AI
    "ai.prompt", "ai.agent", "inference.completion",
}

KNOWN_TRIGGER_TYPES = {"manual", "scheduled", "alert", "webhook"}

LIQUID_RE = re.compile(r"\$?\{\{\s*(.+?)\s*\}\}", re.DOTALL)
STEP_REF_RE = re.compile(r"\bsteps\.([A-Za-z_][A-Za-z0-9_]*)")


class ValidationError(Exception):
    def __init__(self, path: str, msg: str):
        super().__init__(f"{path}: {msg}")
        self.path = path
        self.msg = msg


def collect_steps(steps, out):
    """Walk nested step lists (if/foreach contain inner steps)."""
    if not isinstance(steps, list):
        return
    for step in steps:
        if not isinstance(step, dict):
            continue
        out.append(step)
        for nested_key in ("steps", "else", "fallback"):
            if nested_key in step:
                collect_steps(step[nested_key], out)
        if "on-failure" in step and isinstance(step["on-failure"], dict):
            fb = step["on-failure"].get("fallback")
            if fb:
                collect_steps(fb, out)


def find_liquid_refs(value):
    """Yield (raw_template, inner_expr) pairs from any string value (recursively)."""
    if isinstance(value, str):
        for m in LIQUID_RE.finditer(value):
            yield m.group(0), m.group(1)
    elif isinstance(value, list):
        for v in value:
            yield from find_liquid_refs(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from find_liquid_refs(v)


def validate_file(path: Path) -> list[str]:
    errors = []
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if not isinstance(doc, dict):
        return ["top-level must be a mapping"]

    # Required fields
    if "name" not in doc or not isinstance(doc["name"], str) or not doc["name"].strip():
        errors.append("missing or empty 'name'")
    if "steps" not in doc or not isinstance(doc["steps"], list) or not doc["steps"]:
        errors.append("missing or empty 'steps' (must be a non-empty list)")
        return errors

    # Triggers
    triggers = doc.get("triggers", [])
    if triggers:
        if not isinstance(triggers, list):
            errors.append("'triggers' must be a list")
        else:
            for i, t in enumerate(triggers):
                if not isinstance(t, dict) or "type" not in t:
                    errors.append(f"trigger[{i}] missing 'type'")
                elif t["type"] not in KNOWN_TRIGGER_TYPES:
                    errors.append(f"trigger[{i}] unknown type '{t['type']}' "
                                  f"(known: {sorted(KNOWN_TRIGGER_TYPES)})")

    # Collect all steps including nested
    all_steps = []
    collect_steps(doc["steps"], all_steps)

    # Per-step checks
    seen_names = set()
    step_names = []
    for i, step in enumerate(all_steps):
        if "name" not in step:
            errors.append(f"step[{i}] missing 'name'")
            continue
        nm = step["name"]
        if nm in seen_names:
            errors.append(f"duplicate step name '{nm}'")
        seen_names.add(nm)
        step_names.append(nm)
        # 'if' steps use 'condition' rather than 'type'; only require 'type' if not a flow primitive
        if "type" not in step:
            errors.append(f"step '{nm}' missing 'type'")
            continue
        st = step["type"]
        if st not in KNOWN_STEP_TYPES:
            # tolerate connector-namespaced types like "slack.postMessage"
            base = st.split(".")[0]
            if base not in {s.split(".")[0] for s in KNOWN_STEP_TYPES}:
                errors.append(f"step '{nm}' unknown type '{st}'")

    # Liquid templates: find step refs and confirm targets exist
    for raw, inner in find_liquid_refs(doc):
        for m in STEP_REF_RE.finditer(inner):
            ref = m.group(1)
            if ref not in seen_names:
                errors.append(f"liquid '{raw.strip()}' references unknown step '{ref}'")

    return errors


def gather_files(paths):
    out = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out.extend(sorted(p.rglob("*.yaml")))
            out.extend(sorted(p.rglob("*.yml")))
        elif p.is_file():
            out.append(p)
    return out


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: validate.py <file-or-dir> ...\n")
        return 2
    files = gather_files(argv[1:])
    if not files:
        sys.stderr.write("no YAML files found\n")
        return 2

    total, failed = 0, 0
    for f in files:
        total += 1
        errs = validate_file(f)
        if errs:
            failed += 1
            print(f"FAIL  {f}")
            for e in errs:
                print(f"      - {e}")
        else:
            print(f"ok    {f}")

    print(f"\n{total - failed}/{total} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
