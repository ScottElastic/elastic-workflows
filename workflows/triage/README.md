# Triage workflows

First-response automations that fire on detection-rule alerts and produce an analyst-ready case in under a minute.

| Workflow | Trigger | Connectors / agents | Notes |
|----------|---------|---------------------|-------|
| [`alert-fp-triage-activity-summary.yaml`](alert-fp-triage-activity-summary.yaml) | alert / manual | Inference: `.anthropic-claude-4.6-opus-completion`. Optional Agent Builder agent. | Generic ECS-based FP triage. Auto-closes false positives, escalates true positives. Works with any data source mapped to ECS (`source.ip`, `user.name`, `event.action`, `event.outcome`). Update `consts.kibana_base_url` (or leave as `CHANGEME` to skip case-link rendering). |
| [`mfa-bombing-triage.yaml`](mfa-bombing-triage.yaml) | alert / manual | Slack (token in `consts.slack_token` — replace with `xoxb-...`, or migrate to a Slack connector). | Targets Okta MFA-bombing detections. Pulls sign-in baseline, AI assessment, posts case + Slack summary. |
| [`risky-user-signin-investigation.yaml`](risky-user-signin-investigation.yaml) | alert / manual | Agent Builder agent (`consts.agent_id`). Optional Slack webhook. | Full Entra ID risky sign-in investigation: sign-in details + entity enrichment + audit + Graph + CrowdStrike + PowerShell + Windows logons → AI triage → dashboard tables → hunt queries → six saved searches → case. Update `consts.kibana_base_url` and `consts.logs_data_view_id`. |

## Linking detection rules

For alert-driven workflows, after import: open the detection rule → *Actions* → add the workflow as an action. The full alert document is delivered to the workflow as `event.alerts[0]`.

## Recommended ordering for first-time use

1. Start with `alert-fp-triage-activity-summary.yaml` — it's the most generic and easiest to validate end-to-end.
2. Add `risky-user-signin-investigation.yaml` if you have Entra ID + CrowdStrike data flowing.
3. Add `mfa-bombing-triage.yaml` if you have Okta logs and want a Slack-first triage flow.
