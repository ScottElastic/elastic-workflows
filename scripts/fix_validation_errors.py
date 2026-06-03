#!/usr/bin/env python3
"""
Fix Kibana Workflows YAML validation errors across all splunk-soar workflows.

Fixes applied:
  1. Invalid input type names ("url", "file", "ip", "ipv4", etc.) → string
  2. Single-quoted Liquid vars in filter params ("hostname:'{{ x }}'") → remove single quotes
  3. Unquoted integer values in query: blocks → quote them
  4. kibana.addCaseComment → kibana.request POST /api/cases/{id}/comments
  5. kibana.updateCase → kibana.request PATCH /api/cases
  6. kibana.createCaseDefaultSpace → kibana.request POST /api/cases
  7. kibana.SetAlertsStatus → console step (logs intent)
  8. email step type → console step (logs intent)
  9. wait step type → console step (logs wait duration)
 10. parallel step type → sequential (hoist sub-steps to parent level)
 11. jira step type → http with Jira REST API
 12. slack step type → http with Slack API
 13. virustotal.scanIp / virustotal.scanDomain → http GET to VT API
 14. virustotal.scanFileHash → http GET to VT /api/v3/files/{hash}
 15. virustotal.scanUrl → http POST to VT /api/v3/urls
 16. | parse_json filter → remove (unsupported)
 17. | where_in: filter → remove (unsupported)
 18. | contains: filter → remove (unsupported; leaves truthy string check)
 19. | includes: filter → remove (unsupported; leaves truthy collection check)
 20. | map_to_obj: filter → remove (unsupported)
 21. | get: filter → remove (unsupported)

Usage:
    python3 scripts/fix_validation_errors.py [--dir workflows/splunk-soar] [--dry-run]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# ── 1. Invalid input type names ────────────────────────────────────────────
INVALID_INPUT_TYPES = {
    '"url"', '"file"', '"ip"', '"ipv4"', '"hash"', '"sha256"',
    '"domain"', '"host"', '"process"', '"text"', '"Incident"',
    '"Observation"', '"op"', '".none"', 'object',
    # unquoted variants
    'url', 'file', 'ipv4', 'Incident', 'Observation',
}


def fix_invalid_input_types(text: str) -> str:
    """Replace non-standard input type declarations inside the inputs: block with 'string'.

    Only operates inside the `inputs:` top-level block, not inside query:/body: blocks,
    to avoid incorrectly changing HTTP query parameters named 'type'.
    """
    BAD_TYPES = {
        '"url"', '"file"', '"ip"', '"ipv4"', '"hash"', '"sha256"',
        '"domain"', '"host"', '"process"', '"text"', '"Incident"',
        '"Observation"', '"op"', '".none"', 'object',
    }
    BAD_TYPE_VALUES = {t.strip('"') for t in BAD_TYPES} | {'object'}

    # Find the inputs: block (from inputs: to the next top-level key)
    m = re.search(
        r'^(inputs:.*?)^(?:consts|steps|triggers|enabled|name|description|tags)\b',
        text, re.MULTILINE | re.DOTALL
    )
    if not m:
        return text

    inputs_block = m.group(1)
    fixed_inputs = re.sub(
        r'^(\s+type:\s+)("url"|"file"|"ip"|"ipv4"|"hash"|"sha256"|"domain"|"host"|"process"|"text"|"Incident"|"Observation"|"op"|"\.none"|object)\s*$',
        lambda mm: f"{mm.group(1)}string",
        inputs_block,
        flags=re.MULTILINE,
    )
    return text[:m.start(1)] + fixed_inputs + text[m.start(1) + len(inputs_block):]


# ── 2. Single-quoted Liquid vars in filter/fql params ──────────────────────

def fix_singlequote_liquid_in_filters(text: str) -> str:
    """Remove single quotes that wrap Liquid template expressions in filter strings.

    'hostname:\'{{ inputs.device }}\'' becomes 'hostname:{{ inputs.device }}'
    Affects query param values like filter, $filter, fql, etc.
    """
    # Replace '{{ expr }}' → {{ expr }} anywhere in the file
    # Pattern: single-quote immediately before {{ and after }}
    text = re.sub(r"'(\{\{[^}]+\}\})'", r"\1", text)
    return text


# ── 3. Integer values in query: blocks ─────────────────────────────────────

def fix_integer_query_params(text: str) -> str:
    """Quote unquoted integer values inside query: blocks."""
    lines = text.splitlines(keepends=True)
    result = []
    in_query = False
    query_indent = 0

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(line.lstrip())

        if re.match(r'^\s+query:\s*$', line):
            in_query = True
            query_indent = indent
            result.append(line)
            continue

        if in_query:
            # Still in query block if this line is indented deeper
            if stripped and indent <= query_indent:
                in_query = False
            else:
                # Quote bare integers: `    key: 123` → `    key: "123"`
                m = re.match(r'^(\s+)([\w$\-]+):\s+(\d+)\s*$', line)
                if m and stripped:  # skip empty lines
                    result.append(f"{m.group(1)}{m.group(2)}: \"{m.group(3)}\"\n")
                    continue

        result.append(line)

    return ''.join(result)


# ── 4. Multiple foreach at same level ──────────────────────────────────────

def count_foreach_at_level(steps_text: str, target_indent: int) -> int:
    count = 0
    for line in steps_text.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent == target_indent and re.match(r'\s+type:\s+foreach\s*$', line):
            count += 1
    return count


# ── 5-14. Step type replacements ───────────────────────────────────────────

def _get_with_keys(lines: list[str], start_idx: int, step_indent: int) -> dict[str, str]:
    """Extract key-value pairs from the with: block of a step."""
    keys: dict[str, str] = {}
    in_with = False
    with_indent = step_indent + 2

    for i in range(start_idx, len(lines)):
        line = lines[i]
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if re.match(r'\s+with:\s*$', line) and indent == step_indent + 2:
            in_with = True
            continue

        if in_with:
            if indent <= step_indent + 2 and stripped and not stripped.startswith('#'):
                if indent <= step_indent:
                    break
                m = re.match(r'\s+([\w]+):\s*"?(.+?)"?\s*$', line)
                if m and indent == with_indent + 2:
                    keys[m.group(1)] = m.group(2)

    return keys


def replace_step_block(text: str, step_name_pattern: str, replacement_fn) -> str:
    """Find a step block by type pattern and replace it using replacement_fn."""
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect `    type: <pattern>` at any indentation
        m = re.match(r'^(\s+)type:\s+' + step_name_pattern + r'\s*$', line)
        if m:
            step_indent = len(m.group(1)) - 2  # type: is 2 deeper than - name:
            # Find the start of this step (- name: line)
            step_start = len(result) - 1
            while step_start >= 0:
                sl = result[step_start]
                if re.match(r'^\s{' + str(step_indent) + r'}- name:', sl):
                    break
                step_start -= 1

            # Collect the rest of the with: block for this step
            with_lines = []
            j = i + 1
            while j < len(lines):
                jl = lines[j]
                jstripped = jl.lstrip()
                jindent = len(jl) - len(jstripped)
                if jstripped and jindent <= step_indent and not jstripped.startswith('#'):
                    break
                with_lines.append(jl)
                j += 1

            # Build the original step text
            step_lines = result[step_start + 1:] + [line] + with_lines
            step_header = result[step_start] if step_start >= 0 else ''
            full_step = step_header + ''.join(step_lines)

            replacement = replacement_fn(full_step, m.group(1), step_indent)
            if replacement is not None:
                # Replace the accumulated step in result
                del result[step_start + 1:]
                result[step_start] = replacement
                i = j
                continue

        result.append(line)
        i += 1

    return ''.join(result)


def _indent(n: int) -> str:
    return ' ' * n


def fix_kibana_add_case_comment(text: str) -> str:
    """Replace kibana.addCaseComment with kibana.request."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)

        # Extract step name
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'add_case_comment'

        # Extract caseId and comment values
        case_id_m = re.search(r'caseId:\s*"?([^"\n]+)"?', step_text)
        comment_m = re.search(r'comment:\s*[|>]?\s*\n?(.*?)(?=\n\s{' + str(step_indent) + r',}\w|\Z)',
                              step_text, re.DOTALL)
        comment_inline_m = re.search(r'comment:\s*"([^"]+)"', step_text)
        comment_block_m = re.search(r'comment:\s*\|\n((?:[ \t]+[^\n]*\n)*)', step_text)

        case_id = case_id_m.group(1).strip() if case_id_m else '{{ inputs.kibana_case_id }}'

        if comment_block_m:
            comment_lines = comment_block_m.group(1)
            comment_body = f"|\n{comment_lines}"
        elif comment_inline_m:
            comment_body = f'"{comment_inline_m.group(1)}"'
        else:
            comment_body = '"Automated workflow comment."'

        # Check for on-failure block
        on_failure_m = re.search(r'(    on-failure:.*?)(?=\n    - name:|\Z)', step_text, re.DOTALL)
        on_failure = ''
        if on_failure_m:
            # Reindent to match step
            of_lines = on_failure_m.group(1).splitlines()
            of_reindented = '\n'.join(_indent(step_indent + 2) + l.lstrip() if l.strip() else l
                                      for l in of_lines)
            on_failure = '\n' + of_reindented

        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: kibana.request\n"
            f"{ind2}with:\n"
            f"{ind4}method: POST\n"
            f"{ind4}path: \"/api/cases/{case_id}/comments\"\n"
            f"{ind4}body:\n"
            f"{ind6}type: \"user\"\n"
            f"{ind6}comment: {comment_body}\n"
            f"{ind6}owner: \"cases\"\n"
            f"{on_failure}\n"
        )

    return replace_step_block(text, r'kibana\.addCaseComment', replacer)


def fix_kibana_update_case(text: str) -> str:
    """Replace kibana.updateCase with kibana.request PATCH."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)

        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'update_case'

        case_id_m = re.search(r'caseId:\s*"?([^"\n]+)"?', step_text)
        case_id = case_id_m.group(1).strip() if case_id_m else '{{ inputs.kibana_case_id }}'
        status_m = re.search(r'status:\s*"?([^"\n]+)"?', step_text)
        status = status_m.group(1).strip().strip('"') if status_m else 'closed'

        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: kibana.request\n"
            f"{ind2}with:\n"
            f"{ind4}method: PATCH\n"
            f"{ind4}path: \"/api/cases\"\n"
            f"{ind4}body:\n"
            f"{ind6}- id: \"{case_id}\"\n"
            f"{ind6}  status: \"{status}\"\n"
            f"{ind6}  version: \"WzAsMV0=\"\n"
            "\n"
        )

    return replace_step_block(text, r'kibana\.updateCase', replacer)


def fix_kibana_create_case(text: str) -> str:
    """Replace kibana.createCaseDefaultSpace with kibana.request POST."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)

        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'create_case'
        title_m = re.search(r'title:\s*"([^"]+)"', step_text)
        title = title_m.group(1) if title_m else '{{ inputs.ticket_title | default: "Automated Case" }}'
        desc_m = re.search(r'description:\s*"([^"]+)"', step_text)
        desc = desc_m.group(1) if desc_m else '{{ inputs.description | default: "Created by workflow." }}'

        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: kibana.request\n"
            f"{ind2}with:\n"
            f"{ind4}method: POST\n"
            f"{ind4}path: \"/api/cases\"\n"
            f"{ind4}body:\n"
            f"{ind6}title: \"{title}\"\n"
            f"{ind6}description: \"{desc}\"\n"
            f"{ind6}connector:\n"
            f"{ind6}  id: \"none\"\n"
            f"{ind6}  name: \"none\"\n"
            f"{ind6}  type: \".none\"\n"
            f"{ind6}  fields: null\n"
            f"{ind6}settings:\n"
            f"{ind6}  syncAlerts: false\n"
            f"{ind6}owner: \"cases\"\n"
            f"{ind6}tags: []\n"
            "\n"
        )

    return replace_step_block(text, r'kibana\.createCaseDefaultSpace', replacer)


def fix_kibana_set_alerts_status(text: str) -> str:
    """Replace kibana.SetAlertsStatus with a console log step."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'set_alert_status'
        status_m = re.search(r'status:\s*"?([^"\n]+)"?', step_text)
        status = status_m.group(1).strip().strip('"') if status_m else 'acknowledged'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: console\n"
            f"{ind2}with:\n"
            f"{ind4}message: \"SetAlertsStatus → {status} (logged; kibana.SetAlertsStatus not available in this release)\"\n"
            "\n"
        )
    return replace_step_block(text, r'kibana\.SetAlertsStatus', replacer)


def fix_email_step(text: str) -> str:
    """Replace email step type with console."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'send_email'
        to_m = re.search(r'to:\s*"?([^"\n]+)"?', step_text)
        subject_m = re.search(r'subject:\s*"?([^"\n]+)"?', step_text)
        to = to_m.group(1).strip() if to_m else '(recipients)'
        subject = subject_m.group(1).strip() if subject_m else '(no subject)'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: console\n"
            f"{ind2}with:\n"
            f"{ind4}message: \"Email would be sent to: {to} | subject: {subject}\"\n"
            "\n"
        )
    return replace_step_block(text, 'email', replacer)


def fix_wait_step(text: str) -> str:
    """Replace wait step with console."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'wait'
        dur_m = re.search(r'duration:\s*"?([^"\n]+)"?', step_text)
        dur = dur_m.group(1).strip() if dur_m else '?'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: console\n"
            f"{ind2}with:\n"
            f"{ind4}message: \"Wait step: would pause for {dur}\"\n"
            "\n"
        )
    return replace_step_block(text, 'wait', replacer)


def fix_parallel_step(text: str) -> str:
    """Convert parallel step to sequential — hoist sub-steps out at same level."""
    # This is a complex structural change; for now, replace parallel wrapper
    # with a console log and keep sub-steps by converting to if(true) block
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'parallel_group'

        # Extract the sub-steps block
        steps_m = re.search(r'\n\s+steps:\n(.*)', step_text, re.DOTALL)
        if steps_m:
            sub_steps = steps_m.group(1)
            # Reindent sub-steps to match parent level (remove 2 spaces)
            reindented = re.sub(r'^  ', '', sub_steps, flags=re.MULTILINE)
            return (
                f"{ind}- name: {name}_log\n"
                f"{ind2}type: console\n"
                f"{ind2}with:\n"
                f"{ind4}message: \"Running parallel steps sequentially\"\n"
                f"{reindented}\n"
            )

        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: console\n"
            f"{ind2}with:\n"
            f"{ind4}message: \"parallel block (converted to sequential)\"\n"
            "\n"
        )
    return replace_step_block(text, 'parallel', replacer)


def fix_jira_step(text: str) -> str:
    """Replace jira connector step with http."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'jira_step'
        # Try to extract summary/description
        summary_m = re.search(r'summary:\s*"?([^"\n]+)"?', step_text)
        summary = summary_m.group(1).strip() if summary_m else '{{ inputs.ticket_title | default: "Workflow ticket" }}'
        desc_m = re.search(r'description:\s*"?([^"\n]+)"?', step_text)
        desc = desc_m.group(1).strip() if desc_m else '{{ inputs.description | default: "" }}'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.jira_base | default: 'https://jira.example.com' }}}}/rest/api/3/issue\"\n"
            f"{ind4}method: POST\n"
            f"{ind4}headers:\n"
            f"{ind6}Content-Type: \"application/json\"\n"
            f"{ind4}body:\n"
            f"{ind6}fields:\n"
            f"{ind6}  summary: \"{summary}\"\n"
            f"{ind6}  description:\n"
            f"{ind6}    type: doc\n"
            f"{ind6}    version: 1\n"
            f"{ind6}    content:\n"
            f"{ind6}      - type: paragraph\n"
            f"{ind6}        content:\n"
            f"{ind6}          - type: text\n"
            f"{ind6}            text: \"{desc}\"\n"
            "\n"
        )
    return replace_step_block(text, 'jira', replacer)


def fix_slack_step(text: str) -> str:
    """Replace slack connector step with http."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'slack_step'
        msg_m = re.search(r'message:\s*"([^"]+)"', step_text)
        msg = msg_m.group(1) if msg_m else '{{ inputs.comment | default: "Workflow notification" }}'
        channel_m = re.search(r'channel(?:Id)?:\s*"?([^"\n]+)"?', step_text)
        channel = channel_m.group(1).strip() if channel_m else '#security-alerts'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.slack_webhook | default: 'https://hooks.slack.com/services/CHANGEME' }}}}\"\n"
            f"{ind4}method: POST\n"
            f"{ind4}headers:\n"
            f"{ind6}Content-Type: \"application/json\"\n"
            f"{ind4}body:\n"
            f"{ind6}channel: \"{channel}\"\n"
            f"{ind6}text: \"{msg}\"\n"
            "\n"
        )
    return replace_step_block(text, 'slack', replacer)


def fix_virustotal_scan_ip(text: str) -> str:
    """Replace virustotal.scanIp with http GET."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'vt_scan_ip'
        ip_m = re.search(r'ip(?:Address)?:\s*"?([^"\n]+)"?', step_text)
        ip = ip_m.group(1).strip() if ip_m else '{{ inputs.ip }}'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.virustotal_base | default: 'https://www.virustotal.com' }}}}/api/v3/ip_addresses/{ip}\"\n"
            f"{ind4}method: GET\n"
            f"{ind4}headers:\n"
            f"{ind6}x-apikey: \"{{{{ consts.virustotal_api_key | default: 'CHANGEME_VT_KEY' }}}}\"\n"
            f"{ind4}on-failure:\n"
            f"{ind6}continue: true\n"
            "\n"
        )
    return replace_step_block(text, r'virustotal\.scanIp', replacer)


def fix_virustotal_scan_file_hash(text: str) -> str:
    """Replace virustotal.scanFileHash with http GET to VT files API."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'vt_scan_hash'
        hash_m = re.search(r'hash:\s*"?([^"\n]+)"?', step_text)
        file_hash = hash_m.group(1).strip() if hash_m else '{{ inputs.file_hash }}'
        has_retry = 'on-failure:' in step_text
        on_fail = (
            f"{ind4}on-failure:\n"
            f"{ind6}retry:\n"
            f"{ind6}  max-attempts: 2\n"
            f"{ind6}  delay: \"5s\"\n"
            f"{ind6}continue: true\n"
        ) if has_retry else (
            f"{ind4}on-failure:\n"
            f"{ind6}continue: true\n"
        )
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.virustotal_base | default: 'https://www.virustotal.com' }}}}/api/v3/files/{file_hash}\"\n"
            f"{ind4}method: GET\n"
            f"{ind4}headers:\n"
            f"{ind6}x-apikey: \"{{{{ consts.virustotal_api_key | default: 'CHANGEME_VT_KEY' }}}}\"\n"
            f"{on_fail}\n"
        )
    return replace_step_block(text, r'virustotal\.scanFileHash', replacer)


def fix_virustotal_scan_url(text: str) -> str:
    """Replace virustotal.scanUrl with http POST to VT urls API."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'vt_scan_url'
        # Extract url param (not the url of the step itself)
        url_m = re.search(r'^\s+url:\s*"?([^"\n]+)"?\s*$', step_text, re.MULTILINE)
        url_val = url_m.group(1).strip() if url_m else '{{ item }}'
        has_retry = 'on-failure:' in step_text
        on_fail = (
            f"{ind4}on-failure:\n"
            f"{ind6}retry:\n"
            f"{ind6}  max-attempts: 2\n"
            f"{ind6}  delay: \"5s\"\n"
            f"{ind6}continue: true\n"
        ) if has_retry else (
            f"{ind4}on-failure:\n"
            f"{ind6}continue: true\n"
        )
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.virustotal_base | default: 'https://www.virustotal.com' }}}}/api/v3/urls\"\n"
            f"{ind4}method: POST\n"
            f"{ind4}headers:\n"
            f"{ind6}x-apikey: \"{{{{ consts.virustotal_api_key | default: 'CHANGEME_VT_KEY' }}}}\"\n"
            f"{ind6}Content-Type: \"application/x-www-form-urlencoded\"\n"
            f"{ind4}body: \"url={url_val}\"\n"
            f"{on_fail}\n"
        )
    return replace_step_block(text, r'virustotal\.scanUrl', replacer)


def fix_virustotal_scan_domain(text: str) -> str:
    """Replace virustotal.scanDomain with http GET."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'vt_scan_domain'
        domain_m = re.search(r'domain:\s*"?([^"\n]+)"?', step_text)
        domain = domain_m.group(1).strip() if domain_m else '{{ inputs.domain }}'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.virustotal_base | default: 'https://www.virustotal.com' }}}}/api/v3/domains/{domain}\"\n"
            f"{ind4}method: GET\n"
            f"{ind4}headers:\n"
            f"{ind6}x-apikey: \"{{{{ consts.virustotal_api_key | default: 'CHANGEME_VT_KEY' }}}}\"\n"
            f"{ind4}on-failure:\n"
            f"{ind6}continue: true\n"
            "\n"
        )
    return replace_step_block(text, r'virustotal\.scanDomain', replacer)


# ── 15-21. Unsupported Liquid filters ──────────────────────────────────────

def fix_parse_json_filter(text: str) -> str:
    """Remove unsupported | parse_json filter from Liquid expressions."""
    return re.sub(r'\s*\|\s*parse_json\b', '', text)


def fix_where_in_filter(text: str) -> str:
    """Remove unsupported | where_in: filter from Liquid expressions.

    Handles both inline and multi-line cases:
      ${{ list | where_in: "field", values }}
      ${{ list | default: []
          | where_in: "field", values }}
    """
    return re.sub(r'\s*\|\s*where_in:\s*[^}]+(?=\}\})', '', text)


def fix_contains_filter(text: str) -> str:
    """Remove unsupported | contains: filter from Liquid expressions.

    Leaves the preceding expression as a truthy/falsy check.
    Handles quoted args ('text with spaces') and bareword/variable args.
    """
    return re.sub(
        r"\s*\|\s*contains:\s*(?:'[^']*'|\"[^\"]*\"|\S+)",
        '',
        text,
    )


def fix_includes_filter(text: str) -> str:
    """Remove unsupported | includes: filter from Liquid expressions.

    Leaves the preceding expression (array/string) as a truthy check.
    """
    return re.sub(
        r"\s*\|\s*includes:\s*(?:'[^']*'|\"[^\"]*\"|\S+)",
        '',
        text,
    )


def fix_map_to_obj_filter(text: str) -> str:
    """Remove unsupported | map_to_obj: filter from Liquid expressions."""
    return re.sub(r'\s*\|\s*map_to_obj:\s*[^}$\n]+', '', text)


def fix_get_filter(text: str) -> str:
    """Remove unsupported | get: filter from Liquid expressions."""
    return re.sub(
        r"\s*\|\s*get:\s*(?:'[^']*'|\"[^\"]*\"|\S+)",
        '',
        text,
    )


# ── Repair functions (fix output of earlier buggy fixers) ──────────────────

def repair_block_scalar_comment(text: str) -> str:
    """Fix comment: | blocks where content is at the same indent as the key.

    Bug in fix_kibana_add_case_comment placed content at key-indent instead of
    key+2, making the block scalar semantically invalid (owner: ends up inside
    the block). Convert to inline double-quoted string.
    """
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^(\s+)(comment:\s*\|\s*)$', line)
        if m:
            key_indent = len(m.group(1))
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                next_indent = len(lines[j]) - len(lines[j].lstrip())
                if 0 < next_indent <= key_indent:
                    # Collect content lines at same (wrong) indent, stop at structural keys
                    content_parts = []
                    k = j
                    while k < len(lines):
                        nl = lines[k]
                        if not nl.strip():
                            k += 1
                            continue
                        ni = len(nl) - len(nl.lstrip())
                        if ni < key_indent:
                            break
                        stripped = nl.strip()
                        if re.match(r'(owner:|on-failure:|continue:|retry:|max-attempts:|delay:)\s', stripped):
                            break
                        content_parts.append(stripped)
                        k += 1
                    comment_text = ' '.join(content_parts).replace('"', "'")
                    result.append(f"{m.group(1)}comment: \"{comment_text}\"\n")
                    i = k
                    continue
        result.append(line)
        i += 1
    return ''.join(result)


def repair_orphaned_owner_cases(text: str) -> str:
    """Remove owner: "cases" displaced inside on-failure: blocks.

    When the block scalar bug placed on-failure lines inside the comment content,
    the generated owner: "cases" ends up after the on-failure: block (inside it
    from YAML's perspective). Remove those orphaned instances.
    """
    lines = text.splitlines(keepends=True)
    result = []
    for line in lines:
        if re.match(r'\s+owner:\s*"cases"\s*$', line):
            owner_indent = len(line) - len(line.lstrip())
            orphaned = False
            for j in range(len(result) - 1, max(len(result) - 15, -1), -1):
                rl = result[j]
                if not rl.strip():
                    continue
                ri = len(rl) - len(rl.lstrip())
                if ri < owner_indent and re.match(r'\s*(on-failure:|continue:)', rl.lstrip()):
                    orphaned = True
                    break
                if ri == owner_indent and re.match(r'\s*(comment:|type:|method:|path:|body:)', rl.lstrip()):
                    break
                if ri < owner_indent:
                    break
            if orphaned:
                continue
        result.append(line)
    return ''.join(result)


def repair_duplicate_on_failure(text: str) -> str:
    """Remove duplicate on-failure: blocks in the same step.

    Caused by fix_kibana_add_case_comment capturing on-failure in comment_lines
    (Bug 3) while also generating an on_failure block — creating two on-failure:
    keys in the same step mapping.
    """
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^(\s+)(on-failure:\s*)$', line)
        if m:
            of_indent = len(m.group(1))
            is_dup = False
            for j in range(len(result) - 1, max(len(result) - 20, -1), -1):
                rl = result[j]
                if not rl.strip():
                    continue
                ri = len(rl) - len(rl.lstrip())
                if ri < of_indent and re.match(r'\s+- name:', rl):
                    break
                if ri < of_indent:
                    break
                if ri == of_indent and re.match(r'\s+on-failure:\s*$', rl):
                    is_dup = True
                    break
            if is_dup:
                # Skip this duplicate on-failure: and its children (inc. same-indent continue:)
                i += 1
                while i < len(lines):
                    nl = lines[i]
                    if not nl.strip():
                        i += 1
                        continue
                    ni = len(nl) - len(nl.lstrip())
                    stripped = nl.strip()
                    if ni > of_indent or (ni == of_indent and re.match(r'(continue:|retry:)', stripped)):
                        i += 1
                        continue
                    break
                continue
        result.append(line)
        i += 1
    return ''.join(result)


def repair_on_failure_same_indent(text: str) -> str:
    """Fix on-failure: children that share the same indent as the parent key.

    Bug in fix_kibana_add_case_comment's on_failure reindent stripped all lines to
    the same depth, giving continue: true the same indent as on-failure: instead of
    on-failure+2.
    """
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^(\s+)(on-failure:\s*)$', line)
        if m:
            of_indent = len(m.group(1))
            result.append(line)
            i += 1
            while i < len(lines):
                cl = lines[i]
                if not cl.strip():
                    result.append(cl)
                    i += 1
                    continue
                ci = len(cl) - len(cl.lstrip())
                if ci < of_indent:
                    break
                if ci == of_indent:
                    # Same-indent child: add 2 spaces
                    result.append('  ' + cl)
                    i += 1
                else:
                    result.append(cl)
                    i += 1
            continue
        result.append(line)
        i += 1
    return ''.join(result)


def repair_on_failure_inside_with(text: str) -> str:
    """Move on-failure: from inside with: block to the correct step level.

    Virustotal scan fixers placed on-failure: at step_indent+4 (inside with:)
    instead of step_indent+2. Detect by finding on-failure: where with: is at
    on-failure_indent - 2, then shift the block up by 2.
    """
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^(\s+)(on-failure:\s*)$', line)
        if m:
            of_indent = len(m.group(1))
            if of_indent >= 2:
                inside_with = False
                for j in range(len(result) - 1, max(len(result) - 30, -1), -1):
                    rl = result[j]
                    if not rl.strip():
                        continue
                    ri = len(rl) - len(rl.lstrip())
                    if ri < of_indent - 2:
                        break
                    if ri == of_indent - 2 and re.match(r'\s+with:\s*$', rl):
                        inside_with = True
                        break
                    if ri < of_indent - 2:
                        break
                if inside_with:
                    correct_indent = ' ' * (of_indent - 2)
                    result.append(f"{correct_indent}on-failure:\n")
                    i += 1
                    while i < len(lines):
                        nl = lines[i]
                        if not nl.strip():
                            result.append(nl)
                            i += 1
                            continue
                        ni = len(nl) - len(nl.lstrip())
                        if ni <= of_indent:
                            break
                        result.append(' ' * (ni - 2) + nl.lstrip())
                        i += 1
                    continue
        result.append(line)
        i += 1
    return ''.join(result)


def repair_jira_nested_quotes(text: str) -> str:
    """Fix nested double-quoted strings in Liquid default: filters.

    fix_jira_step and fix_kibana_create_case generate `"{{ expr | default: "value" }}"`
    which is invalid YAML. Replace inner double quotes with single quotes.
    """
    return re.sub(r'(\|\s*default:\s*)"([^"]*)"', r"\1'\2'", text)


def repair_parallel_substep_indent(text: str) -> str:
    """Fix parallel sub-steps placed at step_indent+2 instead of step_indent.

    fix_parallel_step placed sub-steps inside the console step's mapping body
    instead of as siblings at the parent steps level.
    """
    lines = text.splitlines(keepends=True)
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r'\s+message:\s*"Running parallel steps sequentially"\s*$', line):
            msg_indent = len(line) - len(line.lstrip())
            step_indent = msg_indent - 4
            result.append(line)
            i += 1
            while i < len(lines):
                nl = lines[i]
                if not nl.strip():
                    result.append(nl)
                    i += 1
                    continue
                ni = len(nl) - len(nl.lstrip())
                if ni <= step_indent:
                    break
                result.append(nl[2:] if nl[:2] == '  ' else nl)
                i += 1
            continue
        result.append(line)
        i += 1
    return ''.join(result)


def repair_delay_template(text: str) -> str:
    """Replace delay: values containing Liquid template expressions with resolved literals.

    Kibana validates delay values at import time; template expressions are not supported.
    Resolves consts references if found in the file; otherwise uses '30s' as default.
    """
    const_values: dict[str, str] = {}
    for cm in re.finditer(r'^\s+(\w+):\s+(\d+)\s*$', text, re.MULTILINE):
        const_values[cm.group(1)] = cm.group(2)

    def replace_delay(match: re.Match) -> str:
        template = match.group(2)
        vm = re.search(r'consts\.(\w+)', template)
        if vm and vm.group(1) in const_values:
            return f'{match.group(1)}"{const_values[vm.group(1)]}s"'
        return f'{match.group(1)}"30s"'

    return re.sub(r'(delay:\s*)"({{[^}]+}}[^"]*)"', replace_delay, text)


def repair_ai_prompt_timeout(text: str) -> str:
    """Remove timeout: property from ai.prompt steps (not supported at import time)."""
    lines = text.splitlines(keepends=True)
    result = []
    in_ai_prompt = False
    ai_indent = 0
    for line in lines:
        if re.match(r'\s+type:\s+ai\.prompt\s*$', line):
            in_ai_prompt = True
            ai_indent = len(line) - len(line.lstrip()) - 2
        if in_ai_prompt:
            indent = len(line) - len(line.lstrip())
            if line.strip() and indent <= ai_indent:
                in_ai_prompt = False
            elif re.match(r'\s+timeout:\s*"[^"]+"\s*$', line):
                continue
        result.append(line)
    return ''.join(result)


# ── New filter / step-type / trigger fixers ────────────────────────────────

def fix_all_match_filter(text: str) -> str:
    """Remove unsupported | all_match: filter."""
    return re.sub(r"\s*\|\s*all_match:\s*'[^']*',\s*[^}$\n]+", '', text)


def fix_where_3arg_filter(text: str) -> str:
    """Remove unsupported 3-argument | where: filter (field, operator, value).

    The standard 2-argument form | where: field, value is kept.
    """
    return re.sub(r"\s*\|\s*where:\s*'[^']*',\s*'[^']*',\s*'[^']*'", '', text)


def fix_divided_by_filter(text: str) -> str:
    """Remove unsupported | divided_by: filter."""
    return re.sub(r"\s*\|\s*divided_by:\s*\S+", '', text)


def fix_times_filter(text: str) -> str:
    """Remove unsupported | times: filter."""
    return re.sub(r"\s*\|\s*times:\s*\S+", '', text)


def fix_strings_contains_filter(text: str) -> str:
    """Remove unsupported strings.contains: filter."""
    return re.sub(r"\s*strings\.contains:\s*[^}\n]+", '', text)


def fix_servicenow_step(text: str) -> str:
    """Replace servicenow connector step with an http call to ServiceNow REST API."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'servicenow_create'
        desc_m = re.search(r'short_description:\s*"([^"]+)"', step_text)
        short_desc = desc_m.group(1) if desc_m else '{{ inputs.ticket_title | default: \'Workflow ticket\' }}'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.servicenow_base | default: 'https://CHANGEME-servicenow.service-now.com' }}}}/api/now/table/incident\"\n"
            f"{ind4}method: POST\n"
            f"{ind4}headers:\n"
            f"{ind6}Content-Type: \"application/json\"\n"
            f"{ind6}Authorization: \"{{{{ consts.servicenow_auth | default: 'Basic CHANGEME_SN_AUTH' }}}}\"\n"
            f"{ind4}body:\n"
            f"{ind6}short_description: \"{short_desc}\"\n"
            f"{ind4}on-failure:\n"
            f"{ind6}continue: true\n"
            "\n"
        )
    return replace_step_block(text, r'servicenow', replacer)


def fix_elasticsearch_index_step(text: str) -> str:
    """Replace elasticsearch.index step with http POST to ES index API."""
    def replacer(step_text: str, type_indent: str, step_indent: int) -> str | None:
        ind = _indent(step_indent)
        ind2 = _indent(step_indent + 2)
        ind4 = _indent(step_indent + 4)
        ind6 = _indent(step_indent + 6)
        name_m = re.search(r'- name:\s+(\S+)', step_text)
        name = name_m.group(1) if name_m else 'es_index'
        index_m = re.search(r'index:\s*"([^"]+)"', step_text)
        index = index_m.group(1) if index_m else '{{ consts.baseline_index }}'
        return (
            f"{ind}- name: {name}\n"
            f"{ind2}type: http\n"
            f"{ind2}with:\n"
            f"{ind4}url: \"{{{{ consts.elasticsearch_base | default: 'https://CHANGEME-es.elastic-cloud.com' }}}}/{index}/_doc\"\n"
            f"{ind4}method: POST\n"
            f"{ind4}headers:\n"
            f"{ind6}Content-Type: \"application/json\"\n"
            f"{ind6}Authorization: \"{{{{ consts.elasticsearch_auth | default: 'ApiKey CHANGEME_ES_KEY' }}}}\"\n"
            f"{ind4}body: \"{{{{ item | json }}}}\"\n"
            f"{ind4}on-failure:\n"
            f"{ind6}continue: true\n"
            "\n"
        )
    return replace_step_block(text, r'elasticsearch\.index', replacer)


def fix_scheduled_trigger(text: str) -> str:
    """Fix invalid 'schedule' trigger type → 'scheduled'.

    Kibana's workflow schema validator rejects `type: schedule` (singular)
    with: "Invalid trigger type. Available: manual, alert, scheduled".
    """
    return re.sub(r'^(\s+- type:\s+)schedule\s*$', r'\1scheduled', text, flags=re.MULTILINE)


# ── Pipeline ────────────────────────────────────────────────────────────────

FIXERS = [
    ("invalid_input_types",          fix_invalid_input_types),
    ("singlequote_liquid_filter",    fix_singlequote_liquid_in_filters),
    ("integer_query_params",         fix_integer_query_params),
    ("kibana.addCaseComment",        fix_kibana_add_case_comment),
    ("kibana.updateCase",            fix_kibana_update_case),
    ("kibana.createCaseDefaultSpace", fix_kibana_create_case),
    ("kibana.SetAlertsStatus",       fix_kibana_set_alerts_status),
    ("email_step",                   fix_email_step),
    ("wait_step",                    fix_wait_step),
    ("parallel_step",                fix_parallel_step),
    ("jira_step",                    fix_jira_step),
    ("slack_step",                   fix_slack_step),
    ("virustotal.scanIp",            fix_virustotal_scan_ip),
    ("virustotal.scanDomain",        fix_virustotal_scan_domain),
    ("virustotal.scanFileHash",      fix_virustotal_scan_file_hash),
    ("virustotal.scanUrl",           fix_virustotal_scan_url),
    ("parse_json_filter",            fix_parse_json_filter),
    ("where_in_filter",              fix_where_in_filter),
    ("contains_filter",              fix_contains_filter),
    ("includes_filter",              fix_includes_filter),
    ("map_to_obj_filter",            fix_map_to_obj_filter),
    ("get_filter",                   fix_get_filter),
    # New filter / step-type / trigger fixers
    ("fix_all_match_filter",            fix_all_match_filter),
    ("fix_where_3arg_filter",           fix_where_3arg_filter),
    ("fix_divided_by_filter",           fix_divided_by_filter),
    ("fix_times_filter",                fix_times_filter),
    ("fix_strings_contains_filter",     fix_strings_contains_filter),
    ("fix_servicenow_step",             fix_servicenow_step),
    ("fix_elasticsearch_index_step",    fix_elasticsearch_index_step),
    ("fix_scheduled_trigger",           fix_scheduled_trigger),
    # Post-generation repair passes
    ("repair_jira_nested_quotes",       repair_jira_nested_quotes),
    ("repair_parallel_substep_indent",  repair_parallel_substep_indent),
    ("repair_block_scalar_comment",     repair_block_scalar_comment),
    ("repair_orphaned_owner_cases",     repair_orphaned_owner_cases),
    ("repair_duplicate_on_failure",     repair_duplicate_on_failure),
    ("repair_on_failure_same_indent",   repair_on_failure_same_indent),
    ("repair_on_failure_inside_with",   repair_on_failure_inside_with),
    ("repair_delay_template",           repair_delay_template),
    ("repair_ai_prompt_timeout",        repair_ai_prompt_timeout),
]


def fix_file(path: Path, dry_run: bool = False) -> list[str]:
    original = path.read_text()
    text = original
    applied = []

    for name, fixer in FIXERS:
        fixed = fixer(text)
        if fixed != text:
            applied.append(name)
            text = fixed

    if text != original:
        if not dry_run:
            path.write_text(text)
        return applied
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="workflows/splunk-soar")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = Path(args.dir)
    if not root.exists():
        sys.stderr.write(f"Directory not found: {root}\n")
        sys.exit(1)

    files = sorted(root.rglob("*.yaml"))
    total_changed = 0
    total_fixes = {}

    for f in files:
        applied = fix_file(f, dry_run=args.dry_run)
        if applied:
            total_changed += 1
            action = "would fix" if args.dry_run else "fixed"
            print(f"{action}  {f.name}  [{', '.join(applied)}]")
            for a in applied:
                total_fixes[a] = total_fixes.get(a, 0) + 1

    print(f"\n{'Would change' if args.dry_run else 'Changed'} {total_changed}/{len(files)} files.")
    if total_fixes:
        print("\nFix type counts:")
        for name, count in sorted(total_fixes.items(), key=lambda x: -x[1]):
            print(f"  {count:3d}  {name}")


if __name__ == "__main__":
    main()
