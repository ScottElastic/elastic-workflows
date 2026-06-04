#!/usr/bin/env python3
"""
Fix steps that have NO on-failure block at all — these abort the workflow
when they fail, preventing the create_security_case step from running.

Specifically targets:
  - Steps using connector-id: (ai.prompt, etc.) with CHANGEME connectors
  - type: foreach steps whose expression might fail
  - type: kibana.request steps with no on-failure

For every step block that lacks `on-failure:` entirely, appends
`on-failure:\n  continue: true` at the correct indentation before
the next sibling step.

Only processes files with known failure patterns from e2e test.
"""
import re
import glob
import yaml
import os

WORKFLOWS_DIR = os.path.join(os.path.dirname(__file__), '..', 'workflows')


def add_continue_to_steps_without_onfailure(text: str) -> tuple[str, int]:
    """
    For each step block (lines between `  - name:` markers) that:
      - has NO 'on-failure:' line within it
      - is of a type that can fail (ai.prompt, kibana.request, http, foreach)
    Append `on-failure:\n      continue: true` before the next step.
    """
    lines = text.split('\n')
    out = []
    i = 0
    fixes = 0

    while i < len(lines):
        line = lines[i]

        # Detect start of a step list item: "  - name: ..." (2-space indented)
        step_start = re.match(r'^(  - name:.+)$', line)
        if step_start:
            # Collect the whole step block
            step_indent = '  '  # list item indent
            child_indent = '    '  # step body indent
            onfail_indent = '    '

            step_lines = [line]
            j = i + 1
            while j < len(lines):
                nl = lines[j]
                if nl.strip() == '':
                    step_lines.append(nl)
                    j += 1
                    continue
                # Next sibling step or dedent back to parent
                if re.match(r'^  - ', nl) or (nl.strip() and len(nl) - len(nl.lstrip()) <= 2):
                    break
                step_lines.append(nl)
                j += 1

            step_text = '\n'.join(step_lines)

            # Determine if this step type can fail
            type_m = re.search(r'^\s+type:\s+(\S+)', step_text, re.MULTILINE)
            step_type = type_m.group(1) if type_m else ''
            has_connector = bool(re.search(r'connector-id:', step_text))
            failworthy_types = {'http', 'kibana.request', 'ai.prompt', 'foreach',
                                 'ai.inference', 'es.query', 'webhook'}
            is_failworthy = step_type in failworthy_types or has_connector

            has_onfailure = 'on-failure:' in step_text

            if is_failworthy and not has_onfailure:
                # Find the insert point: before trailing blank lines + next step
                # Strip trailing blanks from step_lines, then append on-failure
                while step_lines and step_lines[-1].strip() == '':
                    step_lines.pop()
                step_lines.append(f'{onfail_indent}on-failure:')
                step_lines.append(f'{onfail_indent}  continue: true')
                step_lines.append('')
                fixes += 1

            out.extend(step_lines)
            i = j
        else:
            out.append(line)
            i += 1

    return '\n'.join(out), fixes


def main():
    # Only target files that still have failures after the retry fix
    target_files = [
        'workflows/splunk-soar/investigation/ssh-endpoint-investigate.yaml',
        'workflows/splunk-soar/account-management/aws-find-inactive-users.yaml',
        'workflows/splunk-soar/account-management/azure-new-user-census.yaml',
        'workflows/splunk-soar/remediation/risk-notable-protect-assets-and-users.yaml',
        'workflows/splunk-soar/remediation/rogue-wireless-access-point-remediate.yaml',
        'workflows/splunk-soar/remediation/vmworld-wannacry-response.yaml',
        'workflows/triage/alert-fp-triage-activity-summary.yaml',
        'workflows/triage/mfa-bombing-triage.yaml',
        'workflows/triage/risky-user-signin-investigation.yaml',
        'workflows/investigation/okta-aitm-investigation.yaml',
    ]

    repo_root = os.path.join(os.path.dirname(__file__), '..')
    modified = []
    errors = []

    for rel_path in target_files:
        fpath = os.path.join(repo_root, rel_path)
        if not os.path.exists(fpath):
            print(f"  SKIP (not found): {rel_path}")
            continue

        with open(fpath, 'r', encoding='utf-8') as f:
            original = f.read()

        new_text, fixes = add_continue_to_steps_without_onfailure(original)

        if fixes == 0:
            print(f"  no changes: {os.path.basename(fpath)}")
            continue

        try:
            yaml.safe_load(new_text)
        except yaml.YAMLError as e:
            errors.append((fpath, str(e)))
            print(f"  YAML ERROR: {os.path.basename(fpath)}: {e}")
            continue

        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(new_text)
        modified.append((fpath, fixes))
        print(f"  +{fixes} on-failure:continue blocks → {os.path.basename(fpath)}")

    print(f"\nFixed {len(modified)} files, {sum(f for _,f in modified)} blocks added")
    if errors:
        print(f"Errors: {len(errors)}")


if __name__ == '__main__':
    main()
