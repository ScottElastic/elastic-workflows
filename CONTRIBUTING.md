# Contributing

Thanks for considering a contribution! These workflows are shared as community examples — improvements, bug fixes, and new patterns are welcome.

## Before opening a PR

1. **Sanitize.** Strip every secret and tenant-identifying value:
   - No real Kibana / Elasticsearch URLs (use `YOUR-DEPLOYMENT.kb.REGION.PROVIDER.elastic-cloud.com`).
   - No real API keys, basic-auth headers, bearer tokens, Slack tokens, or webhook URLs.
   - No real usernames, hostnames, IPs, or deployment IDs.
   - No real connector IDs (these are tenant-scoped).
   Quick sweep:
   ```bash
   grep -rEnI 'Basic [A-Za-z0-9+/=]{20,}|Bearer [A-Za-z0-9._-]{20,}|sk-[a-zA-Z0-9]{20,}|xoxb-[a-zA-Z0-9-]{20,}|kb\.[a-z0-9-]+\.cloud\.es\.io' workflows/
   ```

2. **Validate the YAML** — it should parse with any YAML 1.2 parser:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('workflows/<your>.yaml'))"
   ```

3. **Document.** Each workflow's YAML header should describe trigger, data sources, prerequisites, and the customisation steps. Add the workflow to the catalog table in `README.md`.

4. **Use placeholders consistently.** See the customisation checklist in `README.md`.

## Style notes

- Author workflows so they degrade gracefully when optional `consts` aren't filled in (e.g. `{%- if consts.kibana_base_url != "CHANGEME" -%}` around case-link rendering).
- Prefer `ApiKey`-style auth over `Basic` in any direct ES/Kibana HTTP calls.
- Keep AI prompts concise and structured; long unstructured prompts are harder to maintain.
- Add `on-failure` blocks to steps that hit external systems.

## License

By submitting a contribution you agree it will be licensed under the Apache 2.0 license that covers this repo.
