Bifrost Budget
===============

Bifrost Budget is a read-only MCP server that retrieves the caller's quota snapshot from Bifrost and returns normalized budget data with derived remaining values.

This repository includes:

- a Python MCP server implemented with the official MCP SDK
- a quota normalization layer that flattens upstream Bifrost responses into a stable shape
- a container image and Helm chart for deployment
- CI that runs tests and builds a multi-arch Docker image

## Architecture

The server exposes one primary tool:

- `get_quota` — fetches the caller's Bifrost quota snapshot from `GET /api/governance/virtual-keys/quota`

Authentication is read-only and self-service:

- production callers should send an Authorization header to Bifrost, and this service maps that JWT to a Bifrost-recognized virtual key before the quota lookup
- JWT-to-virtual-key exchange for production callers is configured with `BIFROST_AUTH_EXCHANGE_MAP`, a JSON object whose keys are safe claim selectors such as `iss=https://issuer.example.com|sub=user-123`, `preferred_username=alice@example.com`, `email=alice@example.com`, or `sub=user-123`
- for local development or explicit non-production fallback, pass `virtual_key` to the tool directly, send `x-bf-vk` in the MCP request headers with a virtual key, or set `BIFROST_VIRTUAL_KEY` in the runtime environment

The tool never returns the raw virtual key. It only returns derived quota data.

## Configuration

Required:

- `BIFROST_API_BASE_URL` — base URL for the Bifrost API, for example `https://bifrost.example.com`

Optional:

- `BIFROST_QUOTA_PATH` — defaults to `/api/governance/virtual-keys/quota`
- `BIFROST_TIMEOUT_SECONDS` — defaults to `15`
- `BIFROST_LOG_LEVEL` — defaults to `INFO`; controls the structured application logs
- `BIFROST_TRANSPORT` — `streamable-http` (default) or `stdio`
- `BIFROST_HOST` — defaults to `0.0.0.0`
- `BIFROST_PORT` — defaults to `8080`
- `BIFROST_MCP_PATH` — defaults to `/mcp`
- `BIFROST_VIRTUAL_KEY` — fallback caller key for local development or explicit non-production use only
- `BIFROST_AUTH_EXCHANGE_MAP` — JSON object mapping safe JWT claim selectors to Bifrost virtual keys for Authorization-header callers

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
export BIFROST_VIRTUAL_KEY=vk_...
uv run bifrost-budget
```

In production, prefer the caller's `Authorization` header path and do not rely on a static `BIFROST_VIRTUAL_KEY` unless you are intentionally using a fallback.

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
- upstream auth exchange decisions
- tool invocation
- upstream quota requests and responses
- errors

The logs intentionally omit raw virtual keys and Authorization values; at debug level they also show the auth decision tree, including safe claims, redacted configured selector keys, each selector attempt, and the final auth decision. They record only the chosen auth path, the selected outbound auth mode, auth header names, and safe upstream 401 metadata when present.

## Container

Build:

```bash
docker build -t bifrost-budget:local .
```

Run:

```bash
docker run --rm -p 8080:8080 \
  -e BIFROST_API_BASE_URL=https://bifrost.example.com \
  -e BIFROST_VIRTUAL_KEY=vk_... \
  bifrost-budget:local
```

The environment-based key above is a fallback example for local/dev or explicit non-production use. Production deployments should rely on the caller's `Authorization` header path and a configured exchange map.

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
  --set image.tag=latest \
  --set ingress.enabled=true \
  --set ingress.className=traefik \
  --set ingress.hosts[0].host=bifrost-budget.example.internal \
  --set env.apiBaseUrl=https://bifrost.oly.workside.win
```

If you need an explicit fallback key for local/dev or other non-production use, add a secret and wire it into `env.virtualKey.existingSecret`:

```bash
kubectl create secret generic bifrost-budget-vk \
  --from-literal=BIFROST_VIRTUAL_KEY=vk_...
```

Then install with `--set env.virtualKey.existingSecret=bifrost-budget-vk`.

The chart configures readiness and liveness probes against `/healthz` and exposes the MCP server on port 8080.

## Kubernetes examples

The Helm chart is the primary production path, but these plain Kubernetes manifests show the same container wiring in a copy-paste friendly form. They use the GHCR image published by CI and keep auth header-first, so no static Bifrost token is required for production use.

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
          image: ghcr.io/jasonrve/bifrost-budget:latest
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

These examples mirror the chart's container port, service port, and `/healthz`-based probes; use the Helm chart when you want the full production defaults, probes, and optional non-production secret wiring.

## Usage from an MCP client

Clients can call `get_quota` and provide the upstream credential in one of four ways:

1. production path: Authorization header mapped via `BIFROST_AUTH_EXCHANGE_MAP`
2. fallback request header: `x-bf-vk`
3. fallback tool argument: `virtual_key`
4. fallback environment variable: `BIFROST_VIRTUAL_KEY`

The fallback paths are intended for local/dev or explicit non-production use.

The response includes normalized budget rows and a summary with derived totals and remaining values.

## Repository layout

- `src/bifrost_budget/` — server, client, normalization, and settings
- `tests/` — unit and integration tests
- `Dockerfile` — production container image
- `charts/bifrost-budget/` — Helm chart
- `.github/workflows/ci.yml` — test + image build pipeline
