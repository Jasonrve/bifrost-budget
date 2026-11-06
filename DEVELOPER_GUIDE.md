# Developer Guide

## Architecture

Built on [FastMCP](https://gofastmcp.com). `src/bifrost_budget/server.py` owns the `get_quota` tool and `/healthz` route. `client.py` contains asynchronous HTTP calls and authentication separation. `normalization.py` converts governance budgets to the stable response model in `models.py`; `settings.py` validates environment configuration. `logging.py` provides structured, value-free diagnostics.

The production path verifies a delegated-user bearer using the configured Entra provider (default) or explicitly selected Ping provider. `BIFROST_ADMIN_API_KEY` authenticates governance lookup. Never substitute one for the other.

## Local development

Use Python 3.11+ and uv:

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e '.[dev]'
pytest -q
```

Set `BIFROST_API_BASE_URL` for a local run. Do not use real credentials in tests or local logs. The server defaults to Streamable HTTP on `0.0.0.0:8080`, with `/healthz` and `/mcp`. Authenticated `get_quota` requires Streamable HTTP to receive the caller's bearer header; stdio cannot authenticate this tool.

Authentication defaults to Entra and requires tenant, API audience, delegated scope, trusted issuer/discovery/JWKS URLs, and an administrator-managed `(tid,oid) -> exact Bifrost user ID` map. See README for the Entra registration and consent flow. `BIFROST_AUTH_PROVIDER=ping` enables only explicitly configured, JWT-verified Ping migration. UserInfo uses `/userinfo`, not `/clientinfo`, and is subject-bound to the validated token. No Graph API audience or secret is needed by this server. App-only tokens are unsupported. Tool-supplied `api_base_url` is accepted only when it exactly matches the configured backend.

## Tests and quality gates

The test suite uses locally generated signing keys and mocked discovery, JWKS, identity, and Bifrost HTTP responses. It does not contact a live tenant or backend and must not use live credentials. It covers identity resolution, auth separation, malformed input, Decimal arithmetic, structured log redaction, and MCP/health behavior. Run `pytest -q`; run `helm lint charts/bifrost-budget` and, when Docker is available, build the image and verify its configured user with `docker inspect`.

## Dependency updates

Update declared requirements and the lock together:

```bash
uv lock --upgrade
uv lock --check
uv pip compile pyproject.toml --extra dev --generate-hashes -o /tmp/requirements.txt
```

Review the lock diff for compatible stable versions and vulnerability fixes. Do not loosen a security-sensitive dependency to bypass a resolver conflict. Record unavoidable advisories in the release notes or task handoff.

## Logging and redaction rules

Logs are JSON events, not request dumps. Allowed diagnostics are event names, status codes, host/path metadata without query values, parameter names/presence, types, lengths, counts, reason codes, auth-mode labels, and keyed fingerprints. Never log raw headers, Authorization values, API keys, cookies, passwords, identities, JWT claim values, query values, response bodies, exception strings that may contain URLs, or arbitrary upstream objects. Add a regression test whenever a new diagnostic field is introduced. Fingerprints must use `fingerprint_value` and remain operationally sensitive.

### Log levels

`BIFROST_LOG_LEVEL` controls verbosity. Logs contain safe event, status, host/path, count, duration, and reason-code metadata only. They never contain tokens, identities, PII, secrets, query values, response bodies, or unvalidated claim values at any level.

## Release and build workflow

The package version in `pyproject.toml` is canonical. Keep `src/bifrost_budget/__init__.py`, the MCP server metadata, `Dockerfile` default argument, and Helm `Chart.yaml`/default image tag synchronized. Push and pull request workflows run tests and Helm lint without publishing an image. Platform publishes by manually dispatching the workflow with `publish_release=true`; that run checks the immutable semantic tag before publishing multi-architecture SHA, semantic version, and `latest` tags. Prefer an immutable SHA or release tag in deployments.

Before a release, run tests, lock checks, Helm lint, a Docker build, and inspect the diff for secrets. Platform triggers release publication by dispatching the workflow from `main` with `publish_release=true`; ordinary pushes only run checks and builds.

## Contributions

Keep changes focused and preserve the read-only contract. Add or update tests with behavior changes, document configuration changes, avoid unrelated formatting, and do not include secrets or internal identities in fixtures, logs, examples, or commit messages.

## Security review checklist

- [ ] Inbound bearer is used only for caller identity/UserInfo.
- [ ] Governance calls use only the admin key from a secret-backed runtime source.
- [ ] No raw credential, identity, PII, query value, URL query string, or response body can reach logs.
- [ ] Errors expose reason/status context without upstream payloads or credential material.
- [ ] Monetary values use Decimal arithmetic and reject malformed/negative values.
- [ ] Container runs as UID/GID 10001, drops capabilities, and supports read-only root storage.
- [ ] Image references are immutable in deployment configuration.
- [ ] Dependency lock is regenerated and reviewed for advisories.
- [ ] README and examples contain no real credentials or identities.
