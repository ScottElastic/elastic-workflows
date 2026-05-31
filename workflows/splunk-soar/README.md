# Splunk SOAR → Elastic Workflows translations

This directory holds Elastic Workflow YAML files that were translated from
the [Phantom community playbooks](https://github.com/phantomcyber/playbooks)
(Apache 2.0). The originals are visual Splunk SOAR playbooks authored in
Python + Blockly; these are functionally equivalent re-implementations
expressed in the Elastic Workflow YAML DSL.

See [`NOTICE`](NOTICE) for attribution and license details.

## Status

> ⚠️ Tech preview. Elastic Workflows is in tech preview as of 9.x — the YAML
> schema and connector catalog can change. The translations target the
> schema documented in `docs/workflows-reference.md` at the repo root.

## How to use these

1. Pick the workflow you want from one of the category folders below.
2. Open it and search for `CHANGEME` placeholders — these are connector IDs,
   API keys, endpoints, and other deployment-specific values you need to
   fill in for your environment.
3. Wire up any required connectors in **Kibana → Stack Management →
   Connectors** before import. Common ones: ServiceNow, Jira, Slack,
   VirusTotal, OpenAI/Bedrock (for `ai.prompt` steps).
4. Import the YAML into Kibana with the API call documented in
   [`docs/workflows-reference.md`](../../docs/workflows-reference.md), e.g.:

   ```bash
   cat workflows/splunk-soar/account-management/ad-ldap-account-locking.yaml \
     | jq -Rs '{yaml: .}' \
     | curl -sS -X POST "$KIBANA_URL/api/workflows" \
         -H "kbn-xsrf: true" \
         -H "x-elastic-internal-origin: Kibana" \
         -H "Content-Type: application/json" \
         -H "Authorization: ApiKey $KIBANA_API_KEY" \
         -d @-
   ```

## Translation strategy

The originals use Phantom-specific concepts (assets, artifacts, container
metadata, custom-code blocks) that don't have 1:1 Elastic equivalents.
Translations use these substitutions:

| Phantom concept | Elastic equivalent |
|---|---|
| `phantom.act("disable account", assets=["ad ldap"])` | `http` step with TODO (no native AD LDAP connector) |
| `phantom.act("create ticket", assets=["servicenow"])` | `servicenow` connector with `subAction: pushToService` |
| `phantom.act("file reputation", assets=["virustotal"])` | `virustotal.scanFileHash` |
| `phantom.condition(...)` filter blocks | `if` steps with `condition:` |
| `phantom.format(...)` report templates | brief `console` summary, or `data.set` building a structured object |
| Phantom "custom code" Python blocks | Elastic primitives, `ai.prompt`, or TODO |

## Categories

| Category | What lives here |
|---|---|
| [`account-management/`](account-management/) | Disabling, enabling, unlocking, and resetting user accounts across AD, Azure AD, and AWS IAM. Plus alert escalation/de-escalation based on user identity. |
| [`email-triage/`](email-triage/) | Mailbox actions for Gmail and Office 365 (eviction, restore, search-and-purge). Phishing email investigation flows. |
| [`endpoint-response/`](endpoint-response/) | Endpoint actions through CrowdStrike, Microsoft Defender, and Windows Defender — isolation, quarantine, file collection/eviction, process termination. |
| [`enrichment/`](enrichment/) | User and host attribute lookups, identifier activity analysis, dynamic file/URL analysis. |
| [`investigation/`](investigation/) | Multi-step investigations (host triage, log4j hunting, risk-notable workflows, etc.). |
| [`misc/`](misc/) | Tutorials, samples, and one-offs that don't fit elsewhere. |
| [`network-control/`](network-control/) | DNS denylisting, outbound traffic filtering via Cisco Umbrella, Palo Alto Panorama, and Zscaler. |
| [`remediation/`](remediation/) | Containment, file deletion, process termination, indicator blocking, asset protection. |
| [`reputation-analysis/`](reputation-analysis/) | Reputation lookups via VirusTotal, Cisco Talos, PhishTank, ReversingLabs, URLScan. |
| [`threat-intel/`](threat-intel/) | Indicator enrichment via GreyNoise, Recorded Future, Symantec, ThreatQuotient, TruSTAR. |
| [`ticketing/`](ticketing/) | ServiceNow / Jira incident creation, query, update, and related-ticket search. |

## Validation

Lint locally before importing:

```bash
python3 scripts/validator/validate.py workflows/splunk-soar/
```

The validator checks YAML syntax, required fields, known step types, and
referential integrity of `steps.<name>` template expressions.

## Caveats

- **`http` stubs require work to be useful.** Anywhere you see a `# TODO`
  comment near an `http` step, the URL/headers/body are best-effort
  placeholders and you'll need to verify them against the vendor's actual
  API docs before relying on them.
- **No execution validation.** These were lint-checked but not run against
  a live Elastic deployment. Treat each file as a starting point.
- **Phantom custom code was paraphrased, not preserved.** If a source
  playbook had a long inline Python normalization routine, the translation
  describes the intent and either reimplements it with YAML primitives or
  leaves a TODO. Inspect those before relying on them.
- **Apache 2.0 attribution.** See [`NOTICE`](NOTICE) — keep it intact if
  you redistribute this directory.
