#!/usr/bin/env python3
"""Add securitySolution case creation step to all workflows that don't already have it."""

import os
import re
import yaml
import glob

WORKFLOWS_DIR = os.path.join(os.path.dirname(__file__), '..', 'workflows')

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


def get_workflow_name(yaml_text):
    """Extract workflow name from YAML text."""
    for line in yaml_text.split('\n'):
        m = re.match(r'^name:\s*["\']?(.*?)["\']?\s*$', line)
        if m:
            name = m.group(1).strip().strip('"\'')
            # Strip emoji sequences (basic)
            name = re.sub(r'[\U00010000-\U0010ffff]', '', name)
            name = re.sub(r'[\U0001F300-\U0001F9FF]', '', name)
            name = name.strip()
            return name
    return "Unknown Workflow"


def already_has_security_case(yaml_text):
    """Check if workflow already creates a securitySolution case."""
    return 'securitySolution' in yaml_text or 'owner: securitySolution' in yaml_text


def add_case_step(yaml_text, workflow_name):
    """Append case creation step to end of workflow's steps list."""
    # Escape any double-quotes in the workflow name for YAML safety
    safe_name = workflow_name.replace('"', '\\"')
    step_block = CASE_STEP_TEMPLATE.format(workflow_name=safe_name)
    return yaml_text.rstrip() + '\n' + step_block


def main():
    yaml_files = glob.glob(os.path.join(WORKFLOWS_DIR, '**', '*.yaml'), recursive=True)

    modified = []
    skipped_already_has = []
    skipped_no_steps = []
    errors = []

    for fpath in sorted(yaml_files):
        with open(fpath, 'r', encoding='utf-8') as f:
            text = f.read()

        if already_has_security_case(text):
            skipped_already_has.append(fpath)
            continue

        # Must have a steps: section
        if 'steps:' not in text:
            skipped_no_steps.append(fpath)
            continue

        try:
            name = get_workflow_name(text)
            new_text = add_case_step(text, name)

            # Quick validation: try loading the result as YAML
            yaml.safe_load(new_text)

            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(new_text)
            modified.append((fpath, name))
        except Exception as e:
            errors.append((fpath, str(e)))

    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    print(f"Modified:              {len(modified)}")
    print(f"Already had case:      {len(skipped_already_has)}")
    print(f"No steps section:      {len(skipped_no_steps)}")
    print(f"Errors:                {len(errors)}")

    if modified:
        print(f"\nModified files ({len(modified)}):")
        for fpath, name in modified:
            rel = os.path.relpath(fpath, os.path.join(os.path.dirname(__file__), '..'))
            print(f"  + {rel}  [{name}]")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for fpath, err in errors:
            rel = os.path.relpath(fpath, os.path.join(os.path.dirname(__file__), '..'))
            print(f"  ! {rel}: {err}")

    if skipped_no_steps:
        print(f"\nNo steps section ({len(skipped_no_steps)}):")
        for fpath in skipped_no_steps:
            rel = os.path.relpath(fpath, os.path.join(os.path.dirname(__file__), '..'))
            print(f"  - {rel}")


if __name__ == '__main__':
    main()
