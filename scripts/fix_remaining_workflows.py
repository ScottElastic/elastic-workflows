#!/usr/bin/env python3
"""
Fix the 8 workflows that were skipped by add_case_creation.py (they already
had securitySolution owner in existing case logic) and the 2 that have
elasticsearch.esql.query steps without on-failure blocks.

Actions per file:
  1. Add on-failure: continue: true to any step of a failworthy type that
     lacks it entirely (adds elasticsearch.esql.query to the type set).
  2. Append create_security_case step at end (these 8 were skipped before).
"""
import re
import yaml
import os

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')

TARGET_FILES = [
    'workflows/investigation/litellm-trojan-investigation.yaml',
    'workflows/investigation/okta-aitm-investigation.yaml',
    'workflows/splunk-soar/enrichment/acmecorp-phishing-full-triage.yaml',
    'workflows/threat-intel/elastic-security-labs-feed.yaml',
    'workflows/threat-intel/threat-intel-feed-monitor.yaml',
    'workflows/triage/alert-fp-triage-activity-summary.yaml',
    'workflows/triage/mfa-bombing-triage.yaml',
    'workflows/triage/risky-user-signin-investigation.yaml',
]

CASE_STEP_TEMPLATE = '''
  - name: create_security_case
    type: kibana.request
    with:
      method: POST
      path: "/api/cases"
      body:
        title: "Workflow: {workflow_name}"
        description: |
          Automated case created by the **{workflow_name}** workflow.

          Review the workflow execution and attached comments for full investigation details.
        connector:
          id: "none"
          name: "none"
          type: ".none"
          fields: null
        severity: "medium"
        settings:
          syncAlerts: false
        owner: "securitySolution"
        tags: ["automated", "workflow"]
    on-failure:
      continue: true
'''

FAILWORTHY_TYPES = {
    'http', 'kibana.request', 'ai.prompt', 'foreach',
    'ai.inference', 'es.query', 'webhook',
    'elasticsearch.esql.query',  # added — these abort on schema/index errors
}


def get_workflow_name(text: str) -> str:
    for line in text.split('\n'):
        m = re.match(r'^name:\s*["\']?(.*?)["\']?\s*$', line)
        if m:
            name = m.group(1).strip().strip('"\'')
            name = re.sub(r'[\U00010000-\U0010ffff]', '', name)
            name = re.sub(r'[\U0001F300-\U0001F9FF]', '', name)
            return name.strip()
    return 'Unknown Workflow'


def add_continue_to_steps(text: str) -> tuple[str, int]:
    """Add on-failure: continue: true to failworthy steps that lack on-failure."""
    lines = text.split('\n')
    out = []
    i = 0
    fixes = 0

    while i < len(lines):
        line = lines[i]
        step_start = re.match(r'^(  - name:.+)$', line)
        if step_start:
            step_lines = [line]
            j = i + 1
            while j < len(lines):
                nl = lines[j]
                if nl.strip() == '':
                    step_lines.append(nl)
                    j += 1
                    continue
                if re.match(r'^  - ', nl) or (nl.strip() and len(nl) - len(nl.lstrip()) <= 2):
                    break
                step_lines.append(nl)
                j += 1

            step_text = '\n'.join(step_lines)
            type_m = re.search(r'^\s+type:\s+(\S+)', step_text, re.MULTILINE)
            step_type = type_m.group(1) if type_m else ''
            has_connector = bool(re.search(r'connector-id:', step_text))
            is_failworthy = step_type in FAILWORTHY_TYPES or has_connector
            has_onfailure = 'on-failure:' in step_text

            if is_failworthy and not has_onfailure:
                while step_lines and step_lines[-1].strip() == '':
                    step_lines.pop()
                step_lines.append('    on-failure:')
                step_lines.append('      continue: true')
                step_lines.append('')
                fixes += 1

            out.extend(step_lines)
            i = j
        else:
            out.append(line)
            i += 1

    return '\n'.join(out), fixes


def add_case_step(text: str, workflow_name: str) -> str:
    safe_name = workflow_name.replace('"', '\\"')
    step_block = CASE_STEP_TEMPLATE.format(workflow_name=safe_name)
    return text.rstrip() + '\n' + step_block


def main():
    modified = []
    errors = []

    for rel_path in TARGET_FILES:
        fpath = os.path.join(REPO_ROOT, rel_path)
        if not os.path.exists(fpath):
            print(f"  SKIP (not found): {rel_path}")
            continue

        with open(fpath, 'r', encoding='utf-8') as f:
            text = f.read()

        workflow_name = get_workflow_name(text)
        changes = []

        # 1. Add on-failure: continue to failworthy steps
        new_text, n_fixes = add_continue_to_steps(text)
        if n_fixes:
            changes.append(f'+{n_fixes} on-failure blocks')
        text = new_text

        # 2. Append create_security_case if not already present
        if 'create_security_case' not in text:
            text = add_case_step(text, workflow_name)
            changes.append('appended create_security_case')

        if not changes:
            print(f"  no changes: {os.path.basename(fpath)}")
            continue

        try:
            yaml.safe_load(text)
        except yaml.YAMLError as e:
            errors.append((fpath, str(e)))
            print(f"  YAML ERROR: {os.path.basename(fpath)}: {e}")
            continue

        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(text)
        modified.append(fpath)
        print(f"  [{', '.join(changes)}] → {os.path.basename(fpath)}")

    print(f"\nFixed {len(modified)} files")
    if errors:
        print(f"Errors: {errors}")


if __name__ == '__main__':
    main()
