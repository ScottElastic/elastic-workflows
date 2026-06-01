#!/usr/bin/env python3
"""
LLM-backed mock vendor API server. Drop-in replacement for mock_server.py
that uses Amazon Bedrock to synthesize realistic vendor responses on
demand, instead of returning hand-written canned JSON.

Per request:
  1. Compute cache key from (method, path, sorted query params, body).
  2. If hit, serve from cache/<key>.json — no LLM call.
  3. Else, call Bedrock with the request envelope and a system prompt
     that tells the model to act as the appropriate vendor.
  4. Save the response in cache; return it. Subsequent identical
     requests are free and deterministic.

Single non-stdlib dependency: boto3. AWS creds via the standard chain
(env vars, ~/.aws/credentials, or instance role). Bedrock model and
region are env-configurable so you can swap them without editing code.

Env vars:
    BEDROCK_MODEL_ID    default: us.anthropic.claude-sonnet-4-5-20250929-v1:0
    BEDROCK_REGION      default: us-west-2
    CACHE_DIR           default: ./cache
    PORT                default: 8080

Run:
    pip install boto3
    python3 llm_mock_server.py

Smoke test:
    curl -s http://localhost:8080/v1.0/users/test@example.com | jq
    curl -s http://localhost:8080/api/v3/files/$(python3 -c 'print("0"*64)') | jq

Cache:
    rm -rf cache/   # force fresh LLM calls
    Per-file JSON, sha256-keyed. Inspect by hand to see what the LLM made.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import boto3

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
REGION = os.environ.get("BEDROCK_REGION", "us-west-2")
CACHE_DIR = Path(os.environ.get("CACHE_DIR", "./cache"))
PORT = int(os.environ.get("PORT", "8080"))

CACHE_DIR.mkdir(parents=True, exist_ok=True)
bedrock = boto3.client("bedrock-runtime", region_name=REGION)

SYSTEM_PROMPT = """You are a mock vendor API for security automation tests.
You receive an HTTP request and respond with a realistic JSON body that
simulates what the real vendor would return.

Rules:
- Output ONLY a JSON object. No preamble, no code fences, no explanation.
- Identify the vendor + operation from the URL path. Examples:
    /v1.0/users                       Microsoft Graph: wrap list in {"value": [...]}
    /api/now/table/incident           ServiceNow: wrap list in {"result": [...]}
    /api/v3/files/<hash>              VirusTotal: {"data": {"attributes": {...}}}
    /devices/entities/devices/v1      CrowdStrike: {"meta": ..., "resources": [...]}
    ?Action=ListUsers                 AWS IAM query API: {"ListUsersResponse": {"ListUsersResult": {"Users": [...]}}}
    /rest/api/3/issue                 Jira v3: {"issues": [...], "total": N}
    /services/search/jobs             Splunk: {"sid": "..."} or {"results": [...]}
    /api/v1/urlCategories             Zscaler: array at top level
    /v3/community/<ip>                GreyNoise: {"ip": "...", "noise": bool, "classification": "..."}
- Use realistic identifiers (UUIDs, AIDs, sysIds, INC-numbers, base64 tokens),
  ISO 8601 timestamps, plausible names, emails, IPs.
- For LIST operations, return 5-20 items. Mix benign and suspicious so that
  downstream branching logic exercises both paths.
- For GET-one operations, return one rich object with sub-fields populated.
- For destructive actions (delete/quarantine/disable/block), return a
  success envelope including the affected resource id.
- For OAuth/auth endpoints, return a token shaped response with realistic
  expires_in and bearer access_token.
- If the URL is genuinely ambiguous, return {"data": [], "status": "ok"}.
"""


def cache_key(method: str, path: str, query: str, body: bytes) -> str:
    h = hashlib.sha256()
    h.update(method.encode())
    h.update(b"\n")
    h.update(path.encode())
    h.update(b"\n")
    h.update(urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(query))).encode())
    h.update(b"\n")
    h.update(body or b"")
    return h.hexdigest()[:32]


def cache_load(key: str):
    p = CACHE_DIR / f"{key}.json"
    if p.exists():
        return json.loads(p.read_text())["payload"]
    return None


def cache_save(key: str, payload, meta: dict):
    p = CACHE_DIR / f"{key}.json"
    p.write_text(json.dumps({"meta": meta, "payload": payload}, indent=2))


def synth(method: str, path: str, query: str, body: bytes):
    body_str = body.decode("utf-8", "replace") if body else ""
    user_msg = (
        f"Incoming request:\n"
        f"  method: {method}\n"
        f"  path:   {path}\n"
        f"  query:  {query}\n"
        f"  body:   {body_str[:2000]}\n\n"
        f"Return the JSON response body the vendor would send."
    )

    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": user_msg}]}],
        inferenceConfig={"maxTokens": 4096, "temperature": 0.4},
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()

    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip().rstrip("`").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"data": [], "status": "ok", "_mock_note": "LLM returned non-JSON, falling back"}


class Handler(BaseHTTPRequestHandler):
    def _serve(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""

        key = cache_key(method, parsed.path, parsed.query, body)
        cached = cache_load(key)
        if cached is not None:
            payload, source = cached, "cache"
        else:
            try:
                payload = synth(method, parsed.path, parsed.query, body)
                cache_save(key, payload, {"method": method, "path": parsed.path, "query": parsed.query})
            except Exception as e:
                payload = {"data": [], "status": "ok", "_mock_error": str(e)[:200]}
            source = "bedrock"

        out = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("X-Mock-Source", source)
        self.send_header("X-Mock-CacheKey", key)
        self.end_headers()
        self.wfile.write(out)
        sys.stderr.write(f"[{source}] {method} {parsed.path} -> {len(out)}B\n")

    def do_GET(self):    self._serve("GET")
    def do_POST(self):   self._serve("POST")
    def do_PUT(self):    self._serve("PUT")
    def do_DELETE(self): self._serve("DELETE")
    def do_PATCH(self):  self._serve("PATCH")

    def log_message(self, fmt, *args):
        pass


def preflight():
    try:
        bedrock.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "Reply with the word OK."}]}],
            inferenceConfig={"maxTokens": 8},
        )
    except Exception as e:
        sys.stderr.write(f"Bedrock preflight failed: {e}\n")
        sys.stderr.write("Check AWS creds and BEDROCK_MODEL_ID / BEDROCK_REGION.\n")
        sys.exit(1)


def main():
    print(f"LLM mock server")
    print(f"  port:   {PORT}")
    print(f"  model:  {MODEL_ID}")
    print(f"  region: {REGION}")
    print(f"  cache:  {CACHE_DIR.resolve()}")
    print("  verifying Bedrock creds...", end=" ", flush=True)
    preflight()
    print("ok\n")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
