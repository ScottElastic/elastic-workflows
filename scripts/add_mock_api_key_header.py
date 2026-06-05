#!/usr/bin/env python3
"""
Add X-Api-Key: "{{ consts.mock_api_key }}" to every type: http step in all
workflow YAML files. The cloud-hosted mock server requires this header.

Safe to re-run — skips steps that already have X-Api-Key in their headers block.

Usage:
    python3 scripts/add_mock_api_key_header.py          # apply changes
    python3 scripts/add_mock_api_key_header.py --dry-run # preview only
"""
from __future__ import annotations
import glob
import sys
from pathlib import Path

DRY_RUN = "--dry-run" in sys.argv
WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / "workflows"

HEADER_KEY = "X-Api-Key"
HEADER_VALUE = '"{{ consts.mock_api_key }}"'


def leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def process_text(text: str) -> tuple[str, int]:
    """
    Insert X-Api-Key into every type:http step that doesn't already have it.

    Indentation invariants (verified against all 183 http steps):
      - `type: http` is at indent T
      - `with:`, `on-failure:`, etc. are also at indent T (sibling keys)
      - `url:`, `method:`, `headers:` are at T+2 (children of `with:`)
      - header key/value pairs are at T+4 (children of `headers:`)

    Returns (modified_text, number_of_steps_changed).
    """
    lines = text.splitlines(keepends=True)
    changes = 0
    i = 0

    while i < len(lines):
        line = lines[i]

        if line.strip() != "type: http":
            i += 1
            continue

        T = leading_spaces(line)
        with_child = T + 2   # indent of url/method/headers/body/query
        hdr_child  = T + 4   # indent of individual header key: value pairs

        # Scan forward within this step to find:
        #   - the `headers:` line index (or None)
        #   - the last `url:` or `method:` line index (fallback insert point)
        #   - whether X-Api-Key already exists
        in_with_block   = False
        headers_idx     = None
        last_url_meth   = None
        already_has_key = False

        j = i + 1
        while j < len(lines):
            jline    = lines[j]
            jstrip   = jline.strip()
            jspaces  = leading_spaces(jline)

            # Blank lines and comments — skip without breaking
            if not jstrip or jstrip.startswith("#"):
                j += 1
                continue

            # Hit the next list item (indent < T) — step is done
            if jspaces < T:
                break

            # Detect `with:` opening
            if jspaces == T and jstrip == "with:":
                in_with_block = True
                j += 1
                continue

            if not in_with_block:
                j += 1
                continue

            # Inside the with: block — look at keys at with_child depth
            if jspaces == with_child and ":" in jstrip:
                key = jstrip.split(":")[0].strip()
                if key == "headers":
                    headers_idx = j
                elif key in ("url", "method"):
                    last_url_meth = j

            # Look for X-Api-Key inside the headers block
            if headers_idx is not None and jspaces == hdr_child:
                if HEADER_KEY.lower() in jline.lower():
                    already_has_key = True
                    break

            j += 1

        if not already_has_key:
            new_hdr_line = f'{" " * hdr_child}{HEADER_KEY}: {HEADER_VALUE}\n'

            if headers_idx is not None:
                # Insert as the first header after `headers:`
                lines.insert(headers_idx + 1, new_hdr_line)
            elif last_url_meth is not None:
                # No headers block at all — create one after url/method
                new_headers_block = [
                    f'{" " * with_child}headers:\n',
                    new_hdr_line,
                ]
                for nl in reversed(new_headers_block):
                    lines.insert(last_url_meth + 1, nl)
            else:
                # No url or method found (shouldn't happen) — skip
                i += 1
                continue

            changes += 1

        i += 1

    return "".join(lines), changes


def main():
    yaml_files = sorted(glob.glob(str(WORKFLOWS_DIR / "**" / "*.yaml"), recursive=True))

    total_steps = 0
    total_files = 0
    skipped_files = 0

    for path_str in yaml_files:
        path = Path(path_str)
        text = path.read_text()

        new_text, count = process_text(text)

        if count == 0:
            skipped_files += 1
            continue

        total_steps += count
        total_files += 1

        rel = path.relative_to(WORKFLOWS_DIR.parent)
        if DRY_RUN:
            print(f"[dry-run] {rel}  (+{count} header{'s' if count != 1 else ''})")
        else:
            path.write_text(new_text)
            print(f"[updated] {rel}  (+{count} header{'s' if count != 1 else ''})")

    mode = "Would update" if DRY_RUN else "Updated"
    print(f"\n{mode} {total_files} files, {total_steps} http steps "
          f"({skipped_files} files already up-to-date or no http steps).")
    if DRY_RUN:
        print("Re-run without --dry-run to apply.")


if __name__ == "__main__":
    main()
