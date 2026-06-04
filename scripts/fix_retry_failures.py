#!/usr/bin/env python3
"""
Fix the 59 execution failures caused by 'on-failure: retry' blocks
that lack 'continue: true'.

Without 'continue: true', retries exhausted on a CHANGEME/unreachable
URL cause Kibana to FAIL the execution before reaching the appended
create_security_case step at the end.

Fix: for every on-failure block that has 'retry:' but no 'continue: true',
insert 'continue: true' at the correct indentation level.

Also handles the rarer case where the entire on-failure line is a single
inline value (e.g. 'on-failure: continue') — these are already safe and
are left alone.
"""
import re
import glob
import yaml
import os

WORKFLOWS_DIR = os.path.join(os.path.dirname(__file__), '..', 'workflows')


def fix_retry_without_continue(text: str) -> tuple[str, int]:
    """
    Find every multi-line on-failure: block that contains retry: but not
    continue: true and insert continue: true at the right indent.
    Returns (new_text, number_of_blocks_fixed).
    """
    lines = text.split('\n')
    out = []
    i = 0
    fixes = 0

    while i < len(lines):
        line = lines[i]

        # Detect start of a block-form on-failure:
        m = re.match(r'^(\s+)on-failure:\s*$', line)
        if m:
            base_indent = m.group(1)
            child_indent = base_indent + '  '

            # Collect all lines that belong to this on-failure block
            block_lines = [line]
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                # Block ends when we see a non-empty line at <= base_indent level
                if next_line.strip() == '':
                    block_lines.append(next_line)
                    j += 1
                    continue
                indent = len(next_line) - len(next_line.lstrip())
                if indent <= len(base_indent):
                    break
                block_lines.append(next_line)
                j += 1

            block_text = '\n'.join(block_lines)
            has_retry = bool(re.search(r'\n\s+retry:', block_text))
            has_continue = bool(re.search(r'\n\s+continue:', block_text))

            if has_retry and not has_continue:
                # Insert 'continue: true' as first child of on-failure block
                # (right after the 'on-failure:' line itself)
                block_lines.insert(1, f'{child_indent}continue: true')
                fixes += 1

            out.extend(block_lines)
            i = j
        else:
            out.append(line)
            i += 1

    return '\n'.join(out), fixes


def main():
    yaml_files = glob.glob(os.path.join(WORKFLOWS_DIR, '**', '*.yaml'), recursive=True)

    modified = []
    skipped = []
    errors = []

    for fpath in sorted(yaml_files):
        with open(fpath, 'r', encoding='utf-8') as f:
            original = f.read()

        new_text, fixes = fix_retry_without_continue(original)

        if fixes == 0:
            skipped.append(fpath)
            continue

        # Validate YAML before writing
        try:
            yaml.safe_load(new_text)
        except yaml.YAMLError as e:
            errors.append((fpath, str(e)))
            continue

        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(new_text)
        modified.append((fpath, fixes))

    print(f"\n{'='*60}")
    print(f"RETRY FIX RESULTS")
    print(f"{'='*60}")
    print(f"Files fixed:    {len(modified)}")
    print(f"Files unchanged: {len(skipped)}")
    print(f"Errors:         {len(errors)}")

    if modified:
        print(f"\nFixed ({len(modified)} files, {sum(f for _,f in modified)} blocks):")
        for fpath, fixes in modified:
            rel = os.path.relpath(fpath, os.path.join(os.path.dirname(__file__), '..'))
            print(f"  +{fixes} {rel}")

    if errors:
        print(f"\nErrors:")
        for fpath, err in errors:
            print(f"  ! {fpath}: {err}")


if __name__ == '__main__':
    main()
