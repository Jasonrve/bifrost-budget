# Security Policy

Bifrost Budget is a read-only MCP server: it never mutates Bifrost state and never returns raw credentials. See the [security checklist](DEVELOPER_GUIDE.md#security-review-checklist) in the developer guide for the invariants every change must preserve.

## Reporting a vulnerability

Please do not open a public GitHub issue for security reports. Instead, use [GitHub's private vulnerability reporting](https://github.com/Jasonrve/bifrost-budget/security/advisories/new) for this repository, or email the maintainer at jasonrve@gmail.com.

Include:

- A description of the issue and its potential impact.
- Steps to reproduce, or a proof of concept.
- The version or commit SHA you tested against.

You should receive an acknowledgment within a few days. Please give us a reasonable amount of time to address the issue before any public disclosure.

## Supported versions

Only the latest released version is supported. Always pin deployments to an immutable release tag or commit SHA, and keep the dependency lock (`uv.lock`) up to date to pick up upstream security fixes.
