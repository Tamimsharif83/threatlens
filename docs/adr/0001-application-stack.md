# 0001. Application stack

- **Status:** Accepted
- **Date:** 2026-11-08

## Context

ThreatLens must run on an 8 GB laptop from a single `docker run`, use < 300 MB RAM
when idle, work fully offline, and be maintainable by a small team. Its detection
engine is Sigma, whose reference tooling (pySigma and its backends) is Python.
The UI displays attacker-controlled data, so the front end must be easy to lock
down with a strict Content Security Policy.

## Options considered

1. **Python: FastAPI + Jinja2 + HTMX** — same language as pySigma (no
   cross-process bridge); server-rendered HTML is autoescaped by default; HTMX
   adds interactivity with ~50 KB of vendored JS and no build step; FastAPI gives
   typed request validation and OpenAPI docs for free.
2. **Python API + SPA (React/Vue)** — richer client, but needs a Node build
   toolchain, a much larger JS attack surface, and client-side rendering of log
   data (higher XSS risk).
3. **Go or Rust service** — lower memory, but Sigma conversion would need a
   separate Python process or a re-implementation of pySigma (the spec forbids
   hand-writing a Sigma parser).

## Decision

Option 1:

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.13 (supports 3.12+) | pySigma requires ≥ 3.11; 3.13 is current and well supported by wheels |
| Web | FastAPI on Uvicorn | typed, async-capable, OpenAPI; single process |
| HTML | Jinja2 with `autoescape=True` everywhere | escaping is the default, not an opt-in |
| Interactivity | HTMX 2 (vendored), hardened config | no build step; `allowEval=false`, no script execution from swaps |
| Charts | one small vendored library, added when first needed (Phase 1/3) | |
| CLI | Click | small, mature, no extra dependencies |
| Config | pydantic-settings, `TL_` env prefix | validated at startup with readable errors |
| Packaging | uv with a committed `uv.lock` | reproducible builds; fast installs in CI and Docker |
| Quality | ruff (lint + format), mypy `--strict`, pytest + coverage | |
| Logs | stdlib `logging` with a JSON formatter | structured logs without another dependency |

## Consequences

- One process, one language, one container. Simple to run and debug.
- Python's per-process memory is higher than Go's, but measured idle RSS is
  ~58 MiB, well under the 300 MB budget.
- Heavy work (parsing, detection) must be streaming and batched to stay within
  the 1 GB ingest budget; CPU-bound work may need a worker thread so the UI
  stays responsive.
- No client-side framework means complex widgets must be built as
  server-rendered partials. This is a deliberate trade for security.
