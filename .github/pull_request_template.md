## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## How it was tested

<!-- Tests added/updated, manual steps. -->

## Checklist

- [ ] Conventional Commit title (`feat:`, `fix:`, `docs:` …)
- [ ] Tests added or updated; `uv run pytest` passes
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy` are clean
- [ ] CHANGELOG.md updated under **Unreleased**
- [ ] Docs / ADR updated if behaviour or design changed
- [ ] No real logs, secrets or personal data added
- [ ] Log data is never marked safe in templates or put into `innerHTML`; SQL is parameterized
