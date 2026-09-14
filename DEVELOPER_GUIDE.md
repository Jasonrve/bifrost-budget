# Developer Guide

## Architecture

`src/bifrost_budget/server.py` owns the MCP tool and `/healthz` route. `client.py` contains asynchronous HTTP calls and authentication separation. `normalization.py` converts governance budgets to the stable response model in `models.py`; `settings.py` validates environment configuration. `logging.py` provides structured, value-free diagnostics.

The production path is intentionally two-legged: the inbound PingIdentity bearer identifies the caller and is used only for UserInfo fallback; `BIFROST_ADMIN_API_KEY` authenticates governance lookup. Never substitute one for the other.

## Local development

Use Python 3.11+ and uv:

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e '.[dev]'
pytest -q
```

Set `BIFROST_API_BASE_URL` for a local run. Do not use real credentials in tests or local logs. The server defaults to Streamable HTTP on `0.0.0.0:8080`, with `/healthz` and `/mcp`; use `BIFROST_TRANSPORT=stdio` when required by an MCP client.

## Tests and quality gates

The test suite covers identity precedence, URL encoding, auth separation, malformed input, Decimal half-up arithmetic, response fields, structured log redaction, and MCP/health behavior. Run `pytest -q` before committing. Run `helm lint charts/bifrost-budget` and, when Docker is available, build the image and verify its configured user with `docker inspect`.

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

## Release and build workflow

The package version in `pyproject.toml` is canonical. Keep `src/bifrost_budget/__init__.py`, the MCP server metadata, `Dockerfile` default argument, and Helm `Chart.yaml`/default image tag synchronized. CI derives the image version from `pyproject.toml`, runs tests and Helm lint, then publishes multi-architecture images tagged with the commit SHA, semantic version, and `latest`. Prefer the immutable SHA or release tag in deployments; never rely on `latest` for production.

Before a release, run tests, lock checks, Helm lint, a Docker build, and inspect the diff for secrets. Commit with author `Jasonrve <jasonrve@gmail.com>` and push to `main` only after the checks pass.

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
