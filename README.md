<p align="center">
  <img src="https://raw.githubusercontent.com/maximhq/bifrost/main/ui/public/bifrost-logo.png" alt="Bifrost" width="360">
</p>

<h1 align="center">Bifrost Budget</h1>

<p align="center">
  <a href="https://github.com/Jasonrve/bifrost-budget/actions/workflows/ci.yml"><img src="https://github.com/Jasonrve/bifrost-budget/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Jasonrve/bifrost-budget/releases"><img src="https://img.shields.io/github/v/release/Jasonrve/bifrost-budget" alt="Release"></a>

</p>

Bifrost Budget is a read-only Model Context Protocol (MCP) server that retrieves the authenticated caller's Bifrost governance usage and returns normalized dollar quota data. It never mutates Bifrost state or returns credentials.

## Install and run

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e '.[dev]'
export BIFROST_API_BASE_URL=https://bifrost.example.com
export BIFROST_ADMIN_API_KEY= # inject from a secret manager; do not commit it
uv run bifrost-budget
```

The default Streamable HTTP endpoint is `http://localhost:8080/mcp`; health is `GET /healthz`. Set `BIFROST_TRANSPORT=stdio` for stdio clients.

## Configuration

Required: `BIFROST_API_BASE_URL` and `BIFROST_ADMIN_API_KEY`. Optional settings include `BIFROST_QUOTA_PATH`, `BIFROST_USERS_PATH`, `BIFROST_USERINFO_URL`, `BIFROST_TIMEOUT_SECONDS` (15), `BIFROST_LOG_LEVEL` (INFO), `BIFROST_HOST` (0.0.0.0), `BIFROST_PORT` (8080), and `BIFROST_MCP_PATH` (/mcp).

In Kubernetes, configure `env.adminApiKey.existingSecret` in the Helm chart. The chart uses `secretKeyRef`; it does not accept an admin key value. Do not put credentials in images, command lines, manifests, README examples, or logs.

## Authentication and behavior

The inbound `Authorization: Bearer` credential is used only to identify the caller and, when the JWT has no usable `displayname`, to call PingIdentity UserInfo. Identity fallback precedence is JWT `displayname`, UserInfo `name`, then UserInfo `preferred_username`.

The governance request always uses `BIFROST_ADMIN_API_KEY`, never the inbound bearer. The selected identity is URL-encoded in `GET /api/governance/users?search=...&limit=20`. Legacy virtual-key fallback inputs are intentionally not part of the production flow.

The `get_quota` response contains budget rows and a summary. Monetary fields `current_usage`, `max_limit`, and `remaining` are dollar amounts represented as JSON numbers with two decimal places. `remaining` is calculated as `max_limit - current_usage` using Decimal `ROUND_HALF_UP` arithmetic. Missing or malformed monetary input produces an explicit error.

## Troubleshooting and privacy

Structured JSON logs contain event names, status codes, host/path metadata, query parameter names, counts, durations, reason codes, credential modes, lengths, and keyed fingerprints. They never contain bearer tokens, API keys, cookies, raw headers, identities, claim values, response bodies, or query values. Fingerprints are correlation data and should still be protected. Inspect `service_version`, `governance_user_request`, `governance_user_response`, `user_lookup_match`, and `usage_extraction` events first. Confirm the upstream preserves the caller's Authorization header and that the admin key is available through the runtime secret store.

## Immutable container usage

Build locally with `docker build -t bifrost-budget:0.3.8 .`. The image runs as UID/GID 10001, drops Linux capabilities, and is designed for a read-only root filesystem. In production, use the immutable commit SHA or release tag published by CI rather than `latest`:

```bash
docker run --read-only --user 10001:10001 -p 8080:8080 \
  -e BIFROST_API_BASE_URL=https://bifrost.example.com \
  -e BIFROST_ADMIN_API_KEY="$BIFROST_ADMIN_API_KEY" \
  ghcr.io/jasonrve/bifrost-budget:<commit-sha>
```

## Helm

```bash
helm upgrade --install bifrost-budget charts/bifrost-budget \
  --namespace bifrost-budget --create-namespace \
  --set image.tag=0.3.8 \
  --set env.apiBaseUrl=https://bifrost.example.com \
  --set env.adminApiKey.existingSecret=bifrost-budget-admin
```

Pin `image.tag` to a reviewed release or commit SHA. The chart enables non-root execution, drops all capabilities, disables privilege escalation, and uses read-only root storage by default.

## Development

See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for architecture, testing, dependency updates, release workflow, and the security checklist.