# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 9.0.x   | ✅ |
| < 9.0   | ❌ (legacy Python AEGIS — unsupported) |

## Reporting a vulnerability

If you discover a security vulnerability in Obscura Scan **itself** (not in a target
you scanned), please report it responsibly:

- **Do not** open a public issue for security vulnerabilities.
- Email the maintainers or use GitHub's private security advisory at
  <https://github.com/secuity-life-org/Obscura/security/advisories>.
- Include: affected version, a description, reproduction steps, and impact.

We aim to acknowledge reports within a few business days and to ship a fix or
mitigation as quickly as is practical. Please give us reasonable time to remediate
before public disclosure.

## Responsible & authorized use

Obscura Scan is a **dual-use security tool**. It performs active reconnaissance
including exposed-file probing, port scanning, subdomain-takeover detection, and
cloud-bucket enumeration.

- **Only scan systems you own or are explicitly authorized to test.**
- Unauthorized scanning may violate computer-misuse laws in your jurisdiction.
- The authors accept no liability for misuse. See the [LICENSE](LICENSE).

## Built-in safety controls

Obscura Scan is designed to be safe to operate:

- **SSRF guard (default-on).** Every outbound request is dialed through a guarded
  transport that inspects the *resolved* IP at connect time and refuses to connect to:
  loopback (`127.0.0.0/8`, `::1`), link-local incl. cloud metadata
  (`169.254.0.0/16`, `fe80::/10`, `169.254.169.254`), private ranges
  (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), and other reserved/special-use
  ranges. Because the check runs at *connect* time and on every redirect hop, it
  defeats DNS-rebinding and redirect-based bypasses.
  - Override only for authorized internal engagements with `--allow-internal` or
    `OBSCURA_ALLOW_INTERNAL=true` (default: deny).
- **Target validation.** User input is validated/normalized before any module runs.
- **Per-host circuit breaker & bounded concurrency** to avoid hammering targets.
- **Semi-offensive modules are categorized** so operators can choose their scope.
- **Secrets are masked** in the UI, JSON export, and logs; no key is ever logged in
  full.
- **Optional API hardening:** Bearer-token auth, per-IP rate limiting, and an audit
  log on the REST API (`API_AUTH_ENABLED`, `API_RATE_LIMIT_ENABLED`,
  `AUDIT_LOG_ENABLED`).

## Handling of secrets & data

- All API keys are optional and read from the environment / `.env`. They are never
  committed; `.env` is git-ignored.
- API keys are stored only in memory (for provider calls); REST API keys are stored
  as a SHA-256 hash, never in plaintext.
- Scan results are stored locally in SQLite (`obscura.db`). Treat this database as
  sensitive — it contains reconnaissance data about your targets.
