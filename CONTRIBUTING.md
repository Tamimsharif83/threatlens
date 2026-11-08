# Contributing to ThreatLens

Thanks for your interest! ThreatLens is a small project; issues and pull
requests are welcome.

## Ground rules

- **Vendor-neutral:** no code, rules or sample data tied to a specific
  application or personal project.
- **No real logs in git.** Test data comes only from seeded synthetic generators.
  Public datasets are downloaded on demand into a gitignored folder.
- **Secure by default.** Log data is attacker-controlled: never mark it safe in
  templates, never put it in `innerHTML`, always use parameterized SQL.
- **Detection content:** ThreatLens ships only a few *example* rules. Please
  contribute general-purpose detections upstream to
  [SigmaHQ](https://github.com/SigmaHQ/sigma) instead.

## Development setup

```bash
# Python 3.12+ and uv (https://docs.astral.sh/uv/)
uv sync
pre-commit install          # ruff + gitleaks before every commit
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run threatlens serve     # http://127.0.0.1:8080, data in ./data
docker build -t threatlens:dev .
```

## Pull requests

- Small and focused, with tests. CI must be green: lint, format, mypy (strict),
  tests (≥ 80 % coverage on parsers, normalization, detection and correlation),
  Docker build and Trivy scan.
- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat: …`, `fix: …`, `docs: …`, `test: …`, `refactor: …`, `chore: …`, `ci: …`.
- Add an entry under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).
- Significant design decisions get an ADR in [docs/adr/](docs/adr/).

## Reporting security issues

Please don't open a public issue — see [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
