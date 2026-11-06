<p align="center">
  <img src="docs/assets/logo.svg" alt="Bifrost Budget" width="140">
</p>

<h1 align="center">Bifrost Budget</h1>

<p align="center">
  <a href="https://github.com/Jasonrve/bifrost-budget/actions/workflows/ci.yml"><img src="https://github.com/Jasonrve/bifrost-budget/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Jasonrve/bifrost-budget/releases"><img src="https://img.shields.io/github/v/release/Jasonrve/bifrost-budget" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

Bifrost Budget is a read-only [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server, built with [FastMCP](https://gofastmcp.com), that retrieves the authenticated caller's Bifrost governance usage and returns normalized dollar quota data. It never mutates Bifrost state or returns credentials.

## Quickstart with uvx

The fastest way to run the server is with [uv](https://docs.astral.sh/uv/)'s `uvx`, which downloads and runs the package in an isolated environment with no manual install step:

Configure the required Entra settings described below in the process environment before starting it. The sample backend URL and identity values in this guide are placeholders; no production tenant or user mapping is supplied.

```bash
BIFROST_API_BASE_URL=https://bifrost.example.com \
BIFROST_ADMIN_API_KEY=your-admin-key \
uvx bifrost-budget
```

### Adding it to an MCP client (Claude Desktop, Claude Code, etc.)

Authenticated `get_quota` requires Streamable HTTP so the client can send its inbound `Authorization: Bearer ...` header. Stdio cannot carry that request header and is unsupported for `get_quota`; there is no environment-token or virtual-key bypass. Configure an HTTP MCP client with its bearer-token flow, for example:

```json
{
  "mcpServers": {
    "bifrost-budget": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "headers": {"Authorization": "Bearer <user-access-token>"}
    }
  }
}
```

Never commit real values for `BIFROST_ADMIN_API_KEY`; inject it from your client's secret storage or environment.

## Install from source

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e '.[dev]'
export BIFROST_API_BASE_URL=https://bifrost.example.com
export BIFROST_ADMIN_API_KEY= # inject from a secret manager; do not commit it
uv run bifrost-budget
```

The default Streamable HTTP endpoint is `http://localhost:8080/mcp`; health is `GET /healthz`. Stdio may start the process but cannot authenticate `get_quota` because it carries no inbound HTTP Authorization header.

## Configuration

Required: HTTPS `BIFROST_API_BASE_URL`, `BIFROST_ADMIN_API_KEY`, and a complete authentication provider configuration. Loopback HTTP is allowed for local development. Authentication defaults to Entra and fails closed until tenant, audience, delegated scope, trusted discovery/JWKS URLs, and a user mapping are configured. See the setup below. Optional settings include `BIFROST_QUOTA_PATH`, `BIFROST_USERS_PATH`, `BIFROST_TIMEOUT_SECONDS` (15), `BIFROST_LOG_LEVEL` (INFO), `BIFROST_HOST` (0.0.0.0), `BIFROST_PORT` (8080), and `BIFROST_MCP_PATH` (/mcp).

In Kubernetes, configure `env.adminApiKey.existingSecret` in the Helm chart. The chart uses `secretKeyRef`; it does not accept an admin key value. Do not put credentials in images, command lines, manifests, README examples, or logs.

## Authentication and behavior

`BIFROST_AUTH_PROVIDER` defaults to `entra`; set it to `ping` only during an explicitly configured Ping migration. Providers never fall back to one another. Both modes require a strict Bearer JWT signed with RS256 and validated against configured issuer, audience, discovery metadata, JWKS and required lifetime claims. Opaque tokens, unsigned tokens, app-only tokens and ID tokens are rejected. Key rotation uses bounded JWKS refresh; the token cannot select a metadata or key URL.

### Entra delegated-user setup

Register this service as a protected API in Microsoft Entra ID. In the app registration manifest set `api.requestedAccessTokenVersion` to `2`, then expose a delegated scope such as `Quota.Read` (its full scope URI is typically `api://<api-client-id>/Quota.Read`). The `scp` claim contains the bare value `Quota.Read`, which is what `BIFROST_ENTRA_SCOPE` must contain. Grant the calling client consent and request that resource scope using authorization code with PKCE or an applicable delegated/OBO flow. The caller obtains the token; this server needs no client secret.

Set `BIFROST_ENTRA_TENANT_ID`, `BIFROST_ENTRA_AUDIENCE`, and `BIFROST_ENTRA_SCOPE`. For v2 tokens, audience is the API registration's client-ID GUID; it is not automatically the calling client's ID or the `api://...` scope prefix. The default issuer is `https://login.microsoftonline.com/<tenant-guid>/v2.0` and discovery is that issuer plus `/.well-known/openid-configuration`. Set `BIFROST_ENTRA_JWKS_URL` to the exact `jwks_uri` advertised by that tenant discovery document. At runtime, both the discovered issuer and JWKS URI must exactly match the configured values; discovery and key URLs must use HTTPS.

Authorization uses validated immutable `(tid, oid)`. Set `BIFROST_ENTRA_USER_MAP` to a JSON object keyed by lowercase `tenant-guid:user-guid`, whose value is the exact Bifrost governance user ID, for example `{"<tenant-guid>:<user-guid>":"<bifrost-user-id>"}`. This is administrator-managed configuration, not an email/name lookup. Governance search must return one exact, case-sensitive `id` match within the configured bounded page or fail closed. The server does not call Microsoft Graph or require Graph audience, Graph permissions, or a client secret. App-only/service-principal tokens are unsupported.

### Explicit Ping migration mode

Set `BIFROST_AUTH_PROVIDER=ping` and explicitly configure `BIFROST_PING_ISSUER`, `BIFROST_PING_AUDIENCE`, `BIFROST_PING_DISCOVERY_URL`, `BIFROST_PING_JWKS_URL`, `BIFROST_PING_SCOPE`, `BIFROST_USERINFO_URL`, `BIFROST_PING_DELEGATED_CLAIM`, and `BIFROST_PING_DELEGATED_VALUE`. Ping has no endpoint or delegation-marker defaults and startup fails until every value is supplied.

The marker is a signed top-level string claim with an exact configured nonempty string value. It represents a trusted issuer issuance-policy contract: operators must verify that the issuer reserves that claim/value exclusively for delegated human users and configure the actual claim and value. There is no production mapping or suggested claim/value. Do not use `displayname`, `name`, `scope`, `scp`, `sub`, `client_id`, `aud`, `iss`, or another identity/protocol claim as the marker. The subject must be a nonempty immutable human-user subject in the issuer namespace, not a client identity. Known client-credentials grant indicators, explicit `idtyp=app`, and `sub == client_id` are rejected even when the marker matches. Missing, ambiguous, non-string, list, boolean, or wrong marker values fail closed; scope, display claims, and UserInfo alone do not establish delegation. After the contract passes, lookup prefers token `displayname`, then trusted UserInfo response `name`, then `preferred_username`. UserInfo must carry the same `sub` as the validated token. Its URL must be HTTPS without credentials, query, or fragment; redirects are disabled. Legacy name matching must uniquely identify one governance user. The endpoint is `/userinfo`, not `/clientinfo`. Entra remains the default provider and does not need a UserInfo URL or marker configuration.

The governance request always uses `BIFROST_ADMIN_API_KEY`, never the inbound bearer. The tool cannot redirect the configured Bifrost backend. Entra uses exact mapped-ID matching; Ping uses its documented legacy name match. Virtual-key fallback inputs are not part of the production flow.

Governance usage extraction requires `access_profiles` and each profile's `budgets` field to be lists when present, and every profile entry to be an object. Omitted fields are treated as empty for compatibility; explicit `null` or other malformed container values fail the request. Empty lists are valid.

The `get_quota` response contains budget rows and a summary. Monetary fields `current_usage`, `max_limit`, and `remaining` are dollar amounts represented as JSON numbers with two decimal places. `remaining` is calculated as `max_limit - current_usage` using Decimal `ROUND_HALF_UP` arithmetic. Missing or malformed monetary input produces an explicit error.

## Troubleshooting and privacy

Structured JSON logs contain safe event, status, host/path, count, duration, and reason-code metadata. No token, identity, PII, secret, query value, response body, or unvalidated claim value is logged at any level.

## Immutable container usage

Build locally with `docker build -t bifrost-budget:0.5.2 .`. The image runs as UID/GID 10001, drops Linux capabilities, and is designed for a read-only root filesystem. In production, use the immutable commit SHA or release tag published by CI rather than `latest`. Push and pull request CI run checks without publishing. Platform publishes only through `workflow_dispatch` with `publish_release=true`. CI derives the release tag from `pyproject.toml` and refuses to publish if that semantic version already exists in GHCR; SHA, semantic version, and `latest` tags publish together:

```bash
docker run --read-only --user 10001:10001 -p 8080:8080 \
  -e BIFROST_API_BASE_URL=https://bifrost.example.com \
  --env-file /path/to/secure-bifrost-budget.env \
  -e BIFROST_ADMIN_API_KEY="$BIFROST_ADMIN_API_KEY" \
  ghcr.io/jasonrve/bifrost-budget:<commit-sha>
```

## Helm

```bash
helm upgrade --install bifrost-budget charts/bifrost-budget \
  --namespace bifrost-budget --create-namespace \
  --set image.tag=0.5.2 \
  --set env.apiBaseUrl=https://bifrost.example.com \
  --set env.adminApiKey.existingSecret=bifrost-budget-admin
```

Pin `image.tag` to a reviewed release or commit SHA. The chart enables non-root execution, drops all capabilities, disables privilege escalation, and uses read-only root storage by default.
Supply the operator's Entra settings through chart values (`env.entraTenantId`, `env.entraAudience`, `env.entraScope`, `env.entraIssuer`, `env.entraDiscoveryUrl`, `env.entraJwksUrl`, and `env.entraUserMap`) or Ping settings when explicitly migrating, including `env.pingDelegatedClaim` and `env.pingDelegatedValue` after verifying the issuer issuance policy. Defaults intentionally leave required values empty so pods fail closed until configured. Use the Bifrost backend's actual IDs; do not use the placeholders above.

## Development

See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for architecture, testing, dependency updates, release workflow, and the security checklist.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get set up, and please review [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

MIT, see [LICENSE](LICENSE).
