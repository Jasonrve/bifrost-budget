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

- `get_quota` — reads the non-empty trimmed `displayname` claim from the inbound PingIdentity Bearer JWT as the governance search identity, sends `GET /api/governance/users?limit=20` with the configured admin API key, selects the matching governance user, and extracts `access_profiles[*].budgets[*].current_usage`. UserInfo is not an identity fallback.

For the governance response, the server reads the top-level `users` array and compares the derived name against each user's `name`, `username`, `email`, `user_name`, and `id` fields (case-insensitively after trimming). From the first match, every budget containing `current_usage` becomes a normalized row: `current_usage` maps to `consumed`, while `limit` and `unit` are preserved; the normalized summary derives remaining values such as `limit - consumed`.

Authentication is separated by purpose:

- production callers send an Authorization header containing a PingIdentity token; it is sent only to `BIFROST_USERINFO_URL` and the returned `username` is used as the search identity
- the governance request always uses `BIFROST_ADMIN_API_KEY`; the incoming user token is never used as the admin credential

The tool never returns the raw virtual key. It only returns derived quota data.

## Configuration

Required:

- `BIFROST_API_BASE_URL` — base URL for the Bifrost API, for example `https://bifrost.example.com`
- `BIFROST_ADMIN_API_KEY` — admin credential required for governance user lookup; provide through a deployment secret in production. This key is separate from the caller's PingIdentity token.

Optional:

- `BIFROST_QUOTA_PATH` — defaults to `/api/governance/virtual-keys/quota`
- `BIFROST_USERS_PATH` — defaults to `/api/governance/users?limit=20`
- `BIFROST_USERINFO_URL` — defaults to `https://sso-dev.sanlamcloud.co.za/as/userinfo`; retained for optional diagnostics, never used to override JWT `displayname`
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

For the production usage flow, callers must send an `Authorization` header containing the PingIdentity token and the process must receive `BIFROST_ADMIN_API_KEY` through the runtime secret mechanism. The service uses only the token's `displayname` claim (not `sub`, `preferred_username`, JWT `name`, or UserInfo fields) as the governance search identity, while the governance API request uses only the admin key. Missing, empty, or non-string `displayname` returns an explicit error. Static virtual-key fallbacks are for local/dev or explicit non-production use only.

Run the server over stdio:

```bash
export BIFROST_TRANSPORT=stdio
export BIFROST_API_BASE_URL=https://bifrost.example.com
uv run bifrost-budget
```

## Logging and troubleshooting

The server emits structured JSON logs to standard output. Logs cover startup, auth-source selection, tool invocation, the governance-user request and response, matching, usage extraction, and errors. Use the event name (`event`) to group a single troubleshooting attempt; the URL, HTTP status, counts, and duration are operational context, not credentials.

Every process emits one `service_version` event during startup with `version` (the installed `bifrost-budget` package version) and `build_id` (a validated Git SHA when `BIFROST_BUILD_SHA`, `GIT_SHA`, or `SOURCE_COMMIT` is provided, otherwise `unknown`). Use this event to correlate runtime logs with an image tag: for a release, `version` should match the image and Helm tag (currently `0.3.3`), while `build_id` can be matched to the immutable commit-tagged image and deployment revision. Both fields are explicitly `unknown` when unavailable; no configuration values are included.

For a short-lived local diagnostic run only, set `BIFROST_LOG_RAW_HEADERS=true`. Each inbound Streamable HTTP tool request then emits an `inbound_request_headers_cleartext` event containing every header value exactly as received. This is disabled by default and must not be enabled in shared, staging, or production environments because it can log bearer tokens, cookies, and API keys.

### Safe maximal diagnostics (0.3.3)

The `inbound_request_diagnostics` event records every inbound header as `name`, `present`, `value_type`, `value_length`, `value_fingerprint`, and `sensitive`; it never records a header value. Credential-like names are classified sensitive regardless of spelling. Authorization adds `header_present`, `scheme`, `token_length`, `token_fingerprint`, `token_segment_count`, `token_segment_lengths`, `decode_success`, `decode_failure_reason`, `claim_keys`, `claim_metadata`, and `duplicate_claim_keys`. Each `claim_metadata` entry contains only `key`, `value_type`, `value_length`, and `value_fingerprint`.

Identity diagnostics explicitly include `selected_identity_claim`, `identity_extraction_source`, `identity_selection_reason`, `identity_fingerprint`, `identity_length`, `name_present`, and `name_usable`. Governance request/response diagnostics distinguish `inbound_credential: "pingidentity_authorization"` from `outbound_auth_mode: "admin_api_key"` and include only `admin_credential_fingerprint` and `admin_credential_length`. Fingerprints are keyed HMAC-SHA-256 prefixes (the optional `BIFROST_DIAGNOSTIC_FINGERPRINT_KEY` controls the key).

**Security warning:** the default diagnostics are masked or fingerprinted only. They must never be treated as a substitute for access controls. The raw-header diagnostic flag is an explicit exception for local testing and must remain disabled outside that test window. Fingerprints are truncated SHA-256 correlation values and should still be handled as sensitive operational data.

### Distinguish the two credentials

The production flow has two deliberately separate authentication paths:

1. **Inbound PingIdentity credential:** the caller supplies `Authorization: Bearer ***`; the service reads only the JWT `displayname` claim for governance identity. Its safe diagnostic trace can include `auth_source`, `credential_mode`, `token_present`, `scheme`, `token_length`, `token_fingerprint`, `claim_keys`, per-claim `claim_fingerprints`, per-claim `claim_lengths`, and the selected displayname fingerprint. Claim values themselves are never logged.
2. **Outbound governance request:** the service calls `GET /api/governance/users?limit=20` with `BIFROST_ADMIN_API_KEY` as its outbound Bearer credential. The request diagnostic labels this as `outbound_auth_mode: "admin_api_key"` and `inbound_credential: "pingidentity_authorization"`; it records neither the admin key nor an Authorization header value. The inbound PingIdentity token is never reused as the admin credential.

JWT claim diagnostics are retained for troubleshooting token decoding. The source precedence is: inbound JWT `displayname` (required) → no fallback. UserInfo response metadata may be retained for diagnostics, but UserInfo `name`, `username`, and `preferred_username` never become the governance identity.

The upstream proxy/auth middleware must preserve the original `Authorization: Bearer ***` header on the Streamable HTTP request so the JWT `displayname` can be read. The service fails rather than searching by a reduced middleware subject.

### Interpret governance-user diagnostics

The `governance_user_request` event records the request URL, `outbound_auth_mode`, the inbound credential label, and `search_identity_fingerprint` plus `search_identity_length`. The corresponding `governance_user_response` records the HTTP `status_code`. A successful response is followed by `user_lookup_match`, which contains:

- `returned_user_count`: number of entries in the top-level `users` array (non-list or absent arrays are treated as zero);
- `match_count`: number of candidates whose supported identity field matched after trimming and case-folding;
- `candidates`: safe per-candidate metadata, including `candidate_index`, supported `identity_fields`, masked `identity_fingerprints`, and `field_metadata` (`field`, `present`, `value_type`, and, for non-empty strings, fingerprint and trimmed length);
- `match`: whether the candidate matched;
- `matched_fields`: the supported fields that matched (`name`, `username`, `email`, `user_name`, or `id`);
- `match_reason` and `match_reason_detail`: normally `matched`; otherwise the detail identifies `field_absent`, `field_non_string`, or `normalized_mismatch`.

Use these fields to determine whether the PingIdentity-derived identity reached the governance API, whether the API returned candidates, and why each candidate did or did not match. No candidate value is included. On a match, the first matching candidate supplies its `access_profiles[*].budgets[*]`; budgets without `current_usage` are skipped and reported through `malformed_budget_count`.

### Success and no-match behavior

For a successful lookup, expect HTTP 2xx from the governance endpoint, a `user_lookup_match` event with `match_count` greater than zero, and a `usage_extraction` event with the extracted `budget_count`. The tool returns normalized budget rows and a summary with derived totals and remaining values.

If `match_count` is zero, the tool raises `No Bifrost governance user matched the authenticated PingIdentity user` and returns no usage report. This is an expected, actionable no-match outcome—not evidence that the caller's identity should be added to logs. HTTP errors and invalid JSON from the governance endpoint fail the tool with status/type context; they do not expose credential values.

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
  --set image.tag=0.3.3 \
  --set ingress.enabled=true \
  --set ingress.className=traefik \
  --set ingress.hosts[0].host=bifrost-budget.example.internal \
  --set env.apiBaseUrl=https://bifrost.example.com
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

The Helm chart is the primary production path, but these plain Kubernetes manifests show the same container wiring in a copy-paste friendly form. Replace the illustrative image reference (`registry.example.com/your-org/bifrost-budget:<version>`) with an image approved for your environment; keep auth header-first, so no static Bifrost token is required for production use.

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
          image: registry.example.com/your-org/bifrost-budget:<version>
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

Clients can call `get_quota`; the production path requires the caller to provide an `Authorization` header containing a PingIdentity token with a non-empty string `displayname` claim. The server uses that claim for `GET /api/governance/users?limit=20`, authenticated with `BIFROST_ADMIN_API_KEY`.

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
