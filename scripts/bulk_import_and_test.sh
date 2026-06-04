#!/usr/bin/env bash
# Imports all workflows and runs case-creation smoke tests.
# Usage: KIBANA_URL=... KIBANA_API_KEY=... bash scripts/bulk_import_and_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$SCRIPT_DIR/test-harness"
WORKFLOWS_DIR="$SCRIPT_DIR/../workflows"

if [[ -z "${KIBANA_URL:-}" || -z "${KIBANA_API_KEY:-}" ]]; then
  echo "ERROR: KIBANA_URL and KIBANA_API_KEY must be set."
  exit 1
fi

echo "==> Importing workflows..."
python3 "$HARNESS/import_workflows.py" \
  --dir "$WORKFLOWS_DIR" \
  --out "$HARNESS/imported.json"

echo ""
echo "==> Running workflows..."
python3 "$HARNESS/run_workflows.py" \
  --mapping "$HARNESS/imported.json" \
  --out "$HARNESS/results.json"

echo ""
echo "==> Polling executions..."
python3 "$HARNESS/poll_executions.py" \
  --results "$HARNESS/results.json" \
  --out "$HARNESS/final_results.json" 2>&1

echo ""
echo "==> Done. See $HARNESS/final_results.json for full results."
