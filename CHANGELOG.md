# Changelog

## 0.5.1

- Publish a fresh immutable container from the sanitized canonical history; keep existing published versions unchanged.
- Synchronize package, server, container and chart release metadata. Entra remains the default; Ping requires explicit trusted provider and UserInfo configuration.

## 0.5.0

Security migration requiring new deployment configuration:

- Default to Microsoft Entra single-tenant v2 delegated API access tokens; require verified RS256 signatures, exact issuer/audience, lifetime, delegated scope and administrator-managed tenant/object-ID bindings to exact Bifrost user IDs.
- Retain Ping JWT/displayname and subject-bound UserInfo compatibility only with `BIFROST_AUTH_PROVIDER=ping` and explicit trusted provider settings. Opaque/unverified tokens and ambiguous matches are not supported.
- Never use Graph/Ping UserInfo in Entra mode or infer a human user from application credentials. Client-credentials/app-only tokens cannot access current-user budgets.
- Pin governance credential destination to administrator configuration, reject ambiguous users, and remove unverified claim diagnostics from the production flow. Preserve read-only dollar-valued budget responses.
- Synchronize package/server/chart/container version to 0.5.0. Ordinary push/PR CI builds without publishing; Platform explicitly dispatches `publish_release=true` on `main` after verification. Existing semantic image tags must not be overwritten.

Production tenant, API audience, delegated scope and user mappings (or Ping trust settings) must be supplied by the operator. This release is verified with isolated synthetic tokens and HTTP mocks, not a live identity-provider/Bifrost deployment.
