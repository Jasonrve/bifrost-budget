Bifrost Budget
===============

Bifrost Budget is a read-only MCP server that retrieves the authenticated user's usage from Bifrost governance and returns normalized budget data with derived remaining values.

This repository includes:

- a Python MCP server implemented with the official MCP SDK
- a quota normalization layer that flattens upstream Bifrost responses into a stable shape
- a container image and Helm chart for deployment
- CI that runs tests and builds a multi-arch Docker image

## Architecture

The server exposes one primary tool:

- `get_quota` — derives a search name from the incoming PingIdentity token, sends `GET /api/governance/users?limit=20` with the configured admin API key, selects the matching governance user, and extracts `access_profiles[*].budgets[*].current_usage`.

For the governance response, the server reads the top-level `users` array and compares the derived name against each user's `name`, `username`, `email`, `user_name`, and `id` fields (case-insensitively after trimming). From the first match, every budget containing `current_usage` becomes a normalized row: `current_usage` maps to `consumed`, while `limit` and `unit` are preserved; the normalized summary derives remaining values such as `limit - consumed`.

Authentication is separated by purpose:

- production callers send an Authorization header containing a PingIdentity token; only its user name/search identifier is derived locally
- the governance request always uses `BIFROST_ADMIN_API_KEY`; the incoming user token is never used as the admin credential

The tool never returns the raw virtual key. It only returns derived quota data.

## Configuration

Required:

- `BIFROST_API_BASE_URL` — base URL for the Bifrost API, for example `https://bifrost.example.com`
- `BIFROST_ADMIN_API_KEY` — admin credential required for governance user lookup; provide through a deployment secret in production. This key is separate from the caller's PingIdentity token.

Optional:

- `BIFROST_QUOTA_PATH` — defaults to `/api/governance/virtual-keys/quota`
- `BIFROST_USERS_PATH` — defaults to `/api/governance/users?limit=20`
- `BIFROST_TIMEOUT_SECONDS` — defaults to `15`
- `BIFROST_LOG_LEVEL` — defaults to `INFO`; controls the structured application logs
- `BIFROST_TRANSPORT` — `streamable-http` (default) or `stdio`
- `BIFROST_HOST` — defaults to `0.0.0.0`
- `BIFROST_PORT` — defaults to `8080`
- `BIFROST_MCP_PATH` — defaults to `/mcp`


## Local development

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e '.[dev]'
pytest
```

Run the server over HTTP:

```bash
export BIFROST_API_BASE_URL=https://bifrost.example.com
uv run bifrost-budget
```

For the production usage flow, callers must send an `Authorization` header containing the PingIdentity token and the process must receive `BIFROST_ADMIN_API_KEY` through the runtime secret mechanism. The token is used only to derive the governance-user search identity; it is not used to authenticate the governance API request. Static virtual-key fallbacks are for local/dev or explicit non-production use only.

Run the server over stdio:

```bash
export BIFROST_TRANSPORT=stdio
export BIFROST_API_BASE_URL=https://bifrost.example.com
uv run bifrost-budget
```

## Logging

The server emits structured JSON logs to standard output for:

- startup
- auth source selection
- tool invocation
- upstream quota requests and responses
- errors, including missing/invalid credentials, upstream failures, invalid JSON, and no matching governance user

Tokens, Authorization header values, admin API keys, virtual keys, and sensitive token claims are never logged. Diagnostics record only safe event metadata, masked/non-reversible fingerprints, header names, status codes, counts, and timing; identifiers used for correlation are masked or fingerprinted. A no-match response raises `No Bifrost governance user matched the authenticated PingIdentity user` without logging the unmatched identity. Upstream HTTP errors and invalid JSON are returned as tool errors with status/type context, while malformed budget entries are skipped and counted.

### Troubleshooting PingIdentity user matching

User lookup diagnostics include the governance request URL and status, returned user count, the derived search identity's non-reversible fingerprint and length, and per-candidate identity field names, fingerprints, field metadata, match reason, reason detail, and matched fields. Reason details distinguish a successful match, absent supported fields, non-string fields, and normalized value mismatches without exposing values. These fields show whether a PingIdentity `sub` (or another supported claim) maps to a governance `name`, `username`, `email`, `user_name`, or `id` without exposing the values. Logs explicitly distinguish the inbound PingIdentity credential from the outbound `BIFROST_ADMIN_API_KEY` request.

Warning: diagnostics are masked only. They must never be treated as a substitute for access controls, and logs must not contain raw tokens, decoded claim values, email/name/subject values, API keys, or Authorization headers. Fingerprints are intended for correlation and should still be handled as sensitive operational data.

## Container

Build:

```bash
docker build -t bifrost-budget:local .
```

Run:

```bash
docker run --rm -p 8080:8080 \
  -e BIFROST_API_BASE_URL=https://bifrost.example.com \
  bifrost-budget:local
```

For a production container, inject `BIFROST_ADMIN_API_KEY` from the platform's secret store rather than putting a key in an image, command line, manifest, or log. The caller's `Authorization` header supplies the PingIdentity identity used for the lookup.

Health check:

```bash
curl http://localhost:8080/healthz
```

## Helm deployment

Chart path: `charts/bifrost-budget`

Install:

```bash
helm upgrade --install bifrost-budget charts/bifrost-budget \
  --namespace bifrost-budget \
  --create-namespace \
  --set image.tag=0.2.2 \
  --set ingress.enabled=true \
  --set ingress.className=traefik \
  --set ingress.hosts[0].host=bifrost-budget.example.internal \
  --set env.apiBaseUrl=https://bifrost.oly.workside.win
```

For production, create a Kubernetes Secret through your approved secret-management process and configure the chart's admin-key reference. The chart wiring is:

```yaml
env:
  apiBaseUrl: https://bifrost.example.com
  adminApiKey:
    existingSecret: bifrost-budget-admin
    existingSecretKey: BIFROST_ADMIN_API_KEY
```

`charts/bifrost-budget/templates/deployment.yaml` projects that key into the pod as `BIFROST_ADMIN_API_KEY` using `secretKeyRef`; the value is never stored in `values.yaml`. Do not commit a Secret manifest containing a key or pass the key in a command-line argument. The legacy virtual-key fallback, if intentionally enabled for non-production use, is wired separately through `env.virtualKey.existingSecret` and `BIFROST_VIRTUAL_KEY`.

If you need that explicit fallback for local/dev or other non-production use, create the Secret through your secret manager and wire it into `env.virtualKey.existingSecret`; do not put its value in this repository:

```bash
kubectl create secret generic bifrost-budget-vk \
  --from-literal=BIFROST_VIRTUAL_KEY="$BIFROST_VIRTUAL_KEY"
```

Then install with `--set env.virtualKey.existingSecret=bifrost-budget-vk`.

The chart configures readiness and liveness probes against `/healthz` and exposes the MCP server on port 8080.

## Kubernetes examples

The Helm chart is the primary production path, but these plain Kubernetes manifests show the same container wiring in a copy-paste friendly form. They use the GHCR image published by CI (`ghcr.io/jasonrve/bifrost-budget:0.2.2`) and keep auth header-first, so no static Bifrost token is required for production use.

Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bifrost-budget
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: bifrost-budget
  template:
    metadata:
      labels:
        app.kubernetes.io/name: bifrost-budget
    spec:
      containers:
        - name: bifrost-budget
          image: ghcr.io/jasonrve/bifrost-budget:0.2.2
          ports:
            - name: http
              containerPort: 8080
          env:
            - name: BIFROST_API_BASE_URL
              value: https://bifrost.example.com
            - name: BIFROST_TRANSPORT
              value: streamable-http
            - name: BIFROST_MCP_PATH
              value: /mcp
            - name: BIFROST_TIMEOUT_SECONDS
              value: "15"
            - name: BIFROST_ADMIN_API_KEY
              valueFrom:
                secretKeyRef:
                  name: bifrost-budget-admin
                  key: BIFROST_ADMIN_API_KEY
```

Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: bifrost-budget
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: bifrost-budget
  ports:
    - name: http
      port: 80
      targetPort: http
      protocol: TCP
```

These examples mirror the chart's container port, service port, and `/healthz`-based probes; use the Helm chart when you want the full production defaults.

## Usage from an MCP client

Clients can call `get_quota`; the production path requires the caller to provide an `Authorization` header containing a PingIdentity token. The server derives only the user search identity/name from that token, then authenticates `GET /api/governance/users?limit=20` with `BIFROST_ADMIN_API_KEY`.

Legacy/non-production fallback credentials can be supplied in one of three ways:

1. fallback request header: `x-bf-vk`
2. fallback tool argument: `virtual_key`
3. fallback environment variable: `BIFROST_VIRTUAL_KEY`

The fallback paths are intended for local/dev or explicit non-production use.

The response includes normalized budget rows and a summary with derived totals and remaining values.

If no governance user matches the PingIdentity-derived identity, the tool returns a clear no-match error and no usage report. HTTP errors from the governance users endpoint and invalid JSON likewise fail the tool; budgets without `current_usage` are omitted from the report and reflected in diagnostic counts.

If your upstream Bifrost deployment uses a separate enterprise token-exchange layer, configure that outside this server and pass the resulting caller Authorization header through unchanged; this service intentionally no longer remaps callers to virtual keys.

## Repository layout

- `src/bifrost_budget/` — server, client, normalization, and settings
- `tests/` — unit and integration tests
- `Dockerfile` — production container image
- `charts/bifrost-budget/` — Helm chart
- `.github/workflows/ci.yml` — test + image build pipeline
