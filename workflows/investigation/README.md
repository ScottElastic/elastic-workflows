# Investigation workflows

Deeper, multi-phase investigations meant to follow an initial triage. They take longer (multiple AI calls + multiple ES|QL queries) and produce a fully written-up case.

| Workflow | Trigger | Data sources | Notes |
|----------|---------|--------------|-------|
| [`litellm-trojan-investigation.yaml`](litellm-trojan-investigation.yaml) | alert / manual | Endpoint process / network / file telemetry, audit logs. | Investigates a suspected LiteLLM proxy compromise — process tree, environment-variable secrets exposure, network beaconing, AI synthesis. Replace `consts.kibana_base_url`. |
| [`okta-aitm-investigation.yaml`](okta-aitm-investigation.yaml) | alert / manual | `okta.system`, related identity logs. | Okta Adversary-in-the-Middle (AiTM) investigation. Hunts session-token reuse from new IPs/devices, account modifications (password resets, MFA changes, role changes), and OAuth/API-key creation tied to the compromised session. Replace `consts.kibana_base_url` and `consts.logs_data_view_id`. |

## Tips

- These workflows make many AI calls — wire your inference / Agent Builder connectors with sensible per-step timeouts (already set in YAML).
- If a step that depends on a previous AI step is empty, it's almost always because the model timed out. Check execution logs for the failed step before assuming the workflow is broken.
- Saved-search creation requires the data view referenced by `consts.logs_data_view_id` to exist in the same space.
