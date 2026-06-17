# Changelog

All notable changes to Obscura Scan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [9.0.0] — 2026-06-17

The first public release of **Obscura Scan** — a complete, ground-up **Go rewrite**
of the platform formerly known internally as *AEGIS*, re-architected as a single
static binary.

### Added

**Engine & core**
- Single static binary (`CGO_ENABLED=0`, pure Go) — no Python, venv, or system libs.
- Concurrent scan engine: bounded worker pool, dependency DAG, panic isolation per
  module, context cancellation, and result caching.
- SSRF-guarded transport: connect-time IP re-validation (defeats DNS-rebinding and
  redirect bypass), default-deny for loopback/private/link-local/metadata ranges,
  `--allow-internal` / `OBSCURA_ALLOW_INTERNAL` opt-in.
- Shared HTTP client with exponential backoff + jitter, bounded retries, and a
  per-host circuit breaker.
- SQLite (modernc, pure-Go) store in WAL mode with idempotent migrations and a
  repository layer. Imports a legacy `aegis.db` on first start.
- Type-safe configuration loader with alias resolution (`OBSCURA_*` + legacy
  `FLASK_/AEGIS_` aliases, multi-spelling provider keys), validation warnings, and
  secret masking. Every key is optional.

**43 modules** (36 fully keyless)
- DNS: `dns_records`, `dns_zone_transfer`, `dns_bruteforce` (embedded wordlist),
  `subdomain_scan`, `subdomain_permutation`, `reverse_ip`, `whois`.
- TLS/Certs: `tls`, `ssl_chain`, `tls_ciphers` (protocol/cipher audit),
  `jarm_fingerprint`, `cert_transparency`.
- Web: `crawler`, `tech`, `waf_detect`, `sec_headers`, `robots_txt`, `security_txt`,
  `http_methods`, `cors`, `cookie_audit`, `http_probe`, `wayback_urls`.
- JavaScript: `js_endpoints` (LinkFinder-style), `js_secrets`, `source_maps`.
- Email: `spf_analyzer`, `email_security` (DKIM/DMARC/BIMI/MTA-STS/TLS-RPT/DNSSEC/CAA).
- Offense: `port_scan`, `subdomain_takeover`, `cloud_buckets`.
- Intel: `ip_geolocation`, `asn_lookup` (Team Cymru DNS), `typosquat`, `favicon_pivot`,
  `urlscan`, `google_dorking`, and key-gated `virustotal`, `shodan`, `abuseipdb`,
  `greynoise`, `otx`, `securitytrails`.
- Graceful degradation: key-gated modules **skip with a reason**, never fail the scan.

**Scoring & intelligence**
- Self-contained IsolationForest (anomaly scoring) and a transparent weighted risk
  scorer producing a 0–100 score + level.
- Multi-provider AI engine (Gemini → OpenAI → Anthropic) with an always-on offline
  rule-based fallback; copilot chat + scan analysis.

**Web UI & API**
- Embedded, self-contained dark UI (no CDN) with human-readable result rendering
  (risk gauge, findings, per-module tables) and a collapsible raw-JSON fallback.
- Live progress via Server-Sent Events; CSRF on browser POSTs.
- Attack-surface **graph** (target → subdomain → IP → ASN → cert issuer).
- **Compare** two scans (new/resolved findings + risk delta) and analyst **notes**.
- **Settings** page (config, providers, keys masked, API keys, audit log).
- REST API v1 with optional **Bearer auth**, per-IP **rate limiting**, and **audit log**;
  `--mint-key` CLI for key creation.

**Automation**
- Scheduler for recurring scans.
- **Continuous monitoring**: scheduled scans diff against the previous run and send a
  **change alert** for new findings.
- **Campaigns**: bulk multi-target scanning with an aggregated dashboard.
- **Scan templates/profiles**: Quick, Full, Bug Bounty, Compliance.
- Notifications: Slack, Discord, Microsoft Teams, Telegram.

**Exporters & ops**
- 8 formats: JSON, CSV, STIX 2.1, Splunk-CIM, QRadar-LEEF, Elastic-ECS, PDF, DOCX.
- Prometheus `/metrics`, structured `slog` logging, graceful shutdown (SIGINT/SIGTERM).
- Multi-stage Dockerfile (distroless final image), Makefile with cross-compile matrix.

### Notes
- See [MIGRATION_NOTES.md](MIGRATION_NOTES.md) for per-area decisions and deviations
  from the Python original.

[9.0.0]: https://github.com/secuity-life-org/Obscura/releases/tag/v9.0.0
