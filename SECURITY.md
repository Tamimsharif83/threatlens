# Security Policy

ThreatLens processes and displays attacker-controlled data (log files). We treat
vulnerabilities in ThreatLens itself — especially anything that lets log
content execute in an analyst's browser or terminal — as high priority.

## Supported versions

| Version | Supported |
|---|---|
| latest release (`main`) | ✅ |
| older releases | ❌ — please upgrade |

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting instead:
**Security → Report a vulnerability** on
<https://github.com/Tamimsharif83/threatlens/security/advisories/new>.

Please include:

- the ThreatLens version / image tag,
- steps to reproduce (a minimal log sample is ideal),
- the impact you believe it has.

You can expect an acknowledgement within 7 days. We aim to release a fix within
30 days for high/critical issues, and to credit you in the release notes unless
you prefer otherwise.

## Scope

In scope: the ThreatLens application, its container image, and its default
configuration. Examples: XSS from log data, CSRF, authentication or session
flaws, SQL injection, path traversal in uploads, container escape aids,
terminal-escape injection in CLI output, CSV formula injection in exports.

Out of scope: vulnerabilities requiring an already-compromised host or admin
account, deployments that disable the documented hardening, and findings in
third-party dependencies with no demonstrated impact on ThreatLens. Please
report those upstream.

## Hardening guidance

- Keep the port bound to `127.0.0.1` unless you put a TLS reverse proxy in front.
- Run with `--read-only --cap-drop ALL --security-opt no-new-privileges`
  (the default `docker-compose.yml` does).
- Set `TL_COOKIE_SECURE=always` when served over HTTPS.

The security design is documented in
[docs/adr/0003-security-baseline.md](docs/adr/0003-security-baseline.md) and
[docs/adr/0011-v1-hardening.md](docs/adr/0011-v1-hardening.md). The STRIDE
threat model, with the tests behind each control and the accepted residual
risks, is in [docs/threat-model.md](docs/threat-model.md).
