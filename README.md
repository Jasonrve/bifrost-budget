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

- pass `virtual_key` to the tool directly, or
- send `x-bf-vk: <virtual key>` in the MCP request headers, or
- set `BIFROST_VIRTUAL_KEY` in the runtime environment

The tool never returns the raw virtual key. It only returns derived quota data.

## Configuration

Required:

- `BIFROST_API_BASE_URL` — base URL for the Bifrost API, for example `https://bifrost.example.com`

Optional:

- `BIFROST_QUOTA_PATH` — defaults to `/api/governance/virtual-keys/quota`
- `BIFROST_TIMEOUT_SECONDS` — defaults to `15`
- `BIFROST_TRANSPORT` — `streamable-http` (default) or `stdio`
- `BIFROST_HOST` — defaults to `0.0.0.0`
- `BIFROST_PORT` — defaults to `8080`
- `BIFROST_MCP_PATH` — defaults to `/mcp`
- `BIFROST_VIRTUAL_KEY` — fallback caller key for local development only

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

Run the server over stdio:

```bash
export BIFROST_TRANSPORT=stdio
export BIFROST_API_BASE_URL=https://bifrost.example.com
uv run bifrost-budget
```

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

Health check:

```bash
curl http://localhost:8080/healthz
```

## Helm deployment

Chart path: `charts/bifrost-budget`

Install:

```bash
helm upgrade --install bifrost-budget charts/bifrost-budget \
  --set env.apiBaseUrl=https://bifrost.example.com \
  --set env.virtualKey.existingSecret=bifrost-budget-vk
```

Recommended secret:

```bash
kubectl create secret generic bifrost-budget-vk \
  --from-literal=BIFROST_VIRTUAL_KEY=vk_...
```

The chart configures readiness and liveness probes against `/healthz` and exposes the MCP server on port 8080.

## Usage from an MCP client

Clients can call `get_quota` and provide the virtual key in one of three ways:

1. tool argument: `virtual_key`
2. request header: `x-bf-vk`
3. environment variable: `BIFROST_VIRTUAL_KEY`

The response includes normalized budget rows and a summary with derived totals and remaining values.

## Repository layout

- `src/bifrost_budget/` — server, client, normalization, and settings
- `tests/` — unit and integration tests
- `Dockerfile` — production container image
- `charts/bifrost-budget/` — Helm chart
- `.github/workflows/ci.yml` — test + image build pipeline
