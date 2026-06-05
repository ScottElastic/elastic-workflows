# LLM Mock Server

LLM-backed mock vendor API for SOAR workflow testing. Every request gets a realistic,
context-aware JSON response synthesized by Amazon Bedrock. Canonical indicators
(jdoe, 185.220.101.47, DESKTOP-A4K9B2Z, etc.) are pinned to a coherent incident story.

Responses are cached — repeated requests never hit Bedrock twice.

---

## Local development

```bash
cd mock-server
pip install boto3

# Set AWS creds (uses ~/.aws/credentials or env vars as usual)
# API_KEY is optional for local dev — omit it to skip auth
API_KEY=mysecret \
BEDROCK_REGION=us-west-2 \
python3 server.py

# Smoke test
curl http://localhost:8080/health
curl -H "X-Api-Key: mysecret" http://localhost:8080/api/v3/ip_addresses/185.220.101.47 | jq
```

---

## AWS deployment (App Runner)

### Prerequisites

- AWS CLI configured with an account that can create IAM roles, ECR repos, S3 buckets, App Runner services
- Docker installed
- Bedrock model access enabled for `us.anthropic.claude-opus-4-8` in `us-west-2`

Set your account ID once:
```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=us-west-2
```

---

### Step 1 — S3 cache bucket

```bash
aws s3 mb s3://elastic-mock-server-cache --region $AWS_REGION
```

Upload the existing cache to avoid re-generating all responses on first deployment:
```bash
# Run from repo root
aws s3 sync scripts/test-harness/cache s3://elastic-mock-server-cache/cache/
```

---

### Step 2 — ECR Public repository

Private ECR may be blocked by org SCPs. Use ECR Public instead (no auth required for App Runner to pull).
Note: ECR Public is always created in `us-east-1` regardless of the deployment region.

```bash
aws ecr-public create-repository \
  --repository-name elastic-mock-server \
  --region us-east-1 \
  --query 'repository.repositoryUri' --output text
# → public.ecr.aws/<alias>/elastic-mock-server
```

**Already done:** `public.ecr.aws/r2i8h8s4/elastic-mock-server`

---

### Step 3 — IAM instance role for App Runner

This role is used by the running container to call Bedrock and S3.
No separate ECR access role is needed when pulling from ECR Public.

```bash
cat > /tmp/apprunner-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "tasks.apprunner.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
  --role-name elastic-mock-server-role \
  --assume-role-policy-document file:///tmp/apprunner-trust.json

cat > /tmp/apprunner-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:Converse"],
      "Resource": "arn:aws:bedrock:us-west-2::foundation-model/us.anthropic.claude-opus-4-8"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::elastic-mock-server-cache/cache/*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name elastic-mock-server-role \
  --policy-name elastic-mock-server-policy \
  --policy-document file:///tmp/apprunner-policy.json
```

**Already done:** `arn:aws:iam::461485115270:role/elastic-mock-server-role`

---

### Step 4 — Build and push Docker image

ECR Public login always uses `us-east-1` regardless of deployment region.
Build for `linux/amd64` (required on Apple Silicon).

```bash
cd mock-server

# Log in to ECR Public
aws ecr-public get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin public.ecr.aws

# Build
docker build --platform linux/amd64 -t elastic-mock-server .

# Tag and push
docker tag elastic-mock-server:latest \
  public.ecr.aws/r2i8h8s4/elastic-mock-server:latest

docker push public.ecr.aws/r2i8h8s4/elastic-mock-server:latest
```

---

### Step 5 — Generate an API key

```bash
export API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "API_KEY: $API_KEY"   # save this somewhere safe
```

---

### Step 6 — Create the App Runner service

No ECR access role needed for ECR Public images.

```bash
aws apprunner create-service \
  --region us-west-2 \
  --service-name elastic-mock-server \
  --source-configuration '{
    "ImageRepository": {
      "ImageIdentifier": "public.ecr.aws/r2i8h8s4/elastic-mock-server:latest",
      "ImageRepositoryType": "ECR_PUBLIC",
      "ImageConfiguration": {
        "Port": "8080",
        "RuntimeEnvironmentVariables": {
          "API_KEY": "REPLACE_WITH_API_KEY",
          "S3_CACHE_BUCKET": "elastic-mock-server-cache",
          "BEDROCK_REGION": "us-west-2"
        }
      }
    },
    "AutoDeploymentsEnabled": false
  }' \
  --instance-configuration '{
    "Cpu": "0.25 vCPU",
    "Memory": "0.5 GB",
    "InstanceRoleArn": "arn:aws:iam::461485115270:role/elastic-mock-server-role"
  }' \
  --health-check-configuration '{"Protocol":"HTTP","Path":"/health","Interval":10,"Timeout":5,"HealthyThreshold":1,"UnhealthyThreshold":3}'
```

Wait for the service to be running (~2 minutes):
```bash
aws apprunner describe-service \
  --service-arn $(aws apprunner list-services --region $AWS_REGION \
    --query "ServiceSummaryList[?ServiceName=='elastic-mock-server'].ServiceArn" \
    --output text) \
  --region $AWS_REGION \
  --query "Service.Status" --output text
```

Get the public URL:
```bash
export MOCK_URL=$(aws apprunner describe-service \
  --service-arn $(aws apprunner list-services --region us-west-2 \
    --query "ServiceSummaryList[?ServiceName=='elastic-mock-server'].ServiceArn" \
    --output text) \
  --region us-west-2 \
  --query "Service.ServiceUrl" --output text)
echo "https://${MOCK_URL}"
```

**Live URL:** `https://wrxpu2edp7.us-west-2.awsapprunner.com`

Smoke test:
```bash
curl https://wrxpu2edp7.us-west-2.awsapprunner.com/health
curl -H "X-Api-Key: ${API_KEY}" \
  https://wrxpu2edp7.us-west-2.awsapprunner.com/api/v3/ip_addresses/185.220.101.47 | jq .data.attributes.last_analysis_stats
```

---

### Step 7 — Update Kibana workflow constants

In Kibana, go to **Stack Management → Workflow Constants** (or wherever `consts` are managed for your workspace) and update:

| Constant | Old value | New value |
|---|---|---|
| `ngrok_base` | `https://…ngrok-free.dev` | `https://<your-app-runner-url>` |
| `mock_api_key` | *(new)* | your `$API_KEY` value |

Then add `X-Api-Key: "{{ consts.mock_api_key }}"` to the `headers:` block of every `type: http` step in the workflows. A script to do this in bulk:

```bash
# From repo root — adds X-Api-Key header to all workflow http steps
python3 scripts/add_mock_api_key_header.py
```

*(This script doesn't exist yet — create it when ready to migrate workflows.)*

---

## Redeployment (after code changes)

```bash
cd mock-server

aws ecr-public get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin public.ecr.aws

docker build --platform linux/amd64 -t elastic-mock-server .
docker tag elastic-mock-server:latest public.ecr.aws/r2i8h8s4/elastic-mock-server:latest
docker push public.ecr.aws/r2i8h8s4/elastic-mock-server:latest

# Trigger a new App Runner deployment
aws apprunner start-deployment \
  --service-arn $(aws apprunner list-services --region us-west-2 \
    --query "ServiceSummaryList[?ServiceName=='elastic-mock-server'].ServiceArn" \
    --output text) \
  --region us-west-2
```

---

## Cache management

```bash
# List all cached entries
aws s3 ls s3://elastic-mock-server-cache/cache/ | wc -l

# Evict a specific entry (force Bedrock regeneration)
aws s3 rm s3://elastic-mock-server-cache/cache/<key>.json

# Evict all entries with stale 2024 dates
aws s3 ls s3://elastic-mock-server-cache/cache/ --recursive | \
  awk '{print $4}' | xargs -I{} aws s3 cp s3://elastic-mock-server-cache/{} - | \
  grep -l '"2024-' | xargs -I{} aws s3 rm s3://elastic-mock-server-cache/{}

# Nuclear option — clear everything (next request regenerates from Bedrock)
aws s3 rm s3://elastic-mock-server-cache/cache/ --recursive
```

The `X-Mock-CacheKey` response header on every request shows the cache key for that entry.
The `X-Mock-Source` header shows `cache`, `bedrock`, or `hardcoded`.

---

## Environment variables reference

| Variable | Default | Description |
|---|---|---|
| `BEDROCK_MODEL_ID` | `us.anthropic.claude-opus-4-8` | Bedrock model to use for synthesis |
| `BEDROCK_REGION` | `us-west-2` | AWS region for Bedrock calls |
| `S3_CACHE_BUCKET` | *(unset)* | S3 bucket name for cache. Falls back to `CACHE_DIR` if unset. |
| `S3_CACHE_PREFIX` | `cache/` | S3 key prefix for cache objects |
| `CACHE_DIR` | `./cache` | Local cache directory (used when `S3_CACHE_BUCKET` is not set) |
| `API_KEY` | *(unset)* | Shared secret for `X-Api-Key` header. Auth is disabled if unset. |
| `PORT` | `8080` | HTTP port to listen on |

---

## API

### `GET /health`

No auth required. Returns `{"status": "ok", "model": "<model-id>"}`.

### All other endpoints

Pass `X-Api-Key: <API_KEY>` header (when `API_KEY` is configured).
Returns `{"error": "unauthorized"}` with HTTP 401 if missing or wrong.

Response headers on every successful request:
- `X-Mock-Source`: `cache`, `bedrock`, or `hardcoded`
- `X-Mock-CacheKey`: 32-char hex key for this request (use to evict from S3)
