# Contributing

Thanks for considering a contribution to Bifrost Budget.

## Getting set up

```bash
uv venv .venv
. .venv/bin/activate
uv pip install -e '.[dev]'
pytest -q
```

See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for architecture, the release workflow, and the security checklist.

## Making a change

1. Open an issue first for anything beyond a small fix, so the approach can be agreed before you invest time.
2. Keep changes focused; avoid unrelated formatting or refactors in the same diff.
3. Add or update tests for any behavior change. Run `pytest -q` before opening a pull request.
4. If you touch the Helm chart, run `helm lint charts/bifrost-budget`.
5. Never include real credentials, tokens, or internal identities in code, tests, fixtures, or commit messages.

## Pull requests

Describe what changed and why. Link the issue it addresses. CI must pass (tests and Helm lint) before review.

## Reporting bugs

Open a GitHub issue with steps to reproduce, expected vs. actual behavior, and relevant log excerpts (redacted of any credentials). For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of filing a public issue.
