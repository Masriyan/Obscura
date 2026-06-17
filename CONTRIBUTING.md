# Contributing to Obscura Scan

Thanks for your interest in improving Obscura Scan! This guide covers the dev
setup, how to add a module, and the contribution workflow.

## Ground rules

- **Authorized use only.** Obscura Scan performs active recon. Do not contribute
  features designed for mass-targeting, DoS, or evading detection for malicious use.
- Keep the binary **dependency-light and pure Go** (`CGO_ENABLED=0`). Prefer the
  standard library; justify any new third-party dependency in your PR.
- Match the surrounding code's style and idioms.

## Development setup

Requirements: **Go 1.25+**. No CGO, no system libraries.

```bash
git clone https://github.com/secuity-life-org/Obscura.git
cd Obscura

make build        # build the binary -> bin/obscura
make test         # go test -race ./...
make lint         # gofmt check + go vet
make run          # build and run
```

Before opening a PR, make sure all of these are clean:

```bash
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build ./...
```

## Project layout

See the Architecture section of the [README](README.md#architecture). In short:
`internal/engine` is the orchestrator, `internal/modules` holds one file per scan
module, `internal/server` is the web/API layer, and everything user-facing
(templates, static, wordlists) is embedded with `//go:embed`.

## Adding a scan module

Modules implement the `engine.Module` interface and self-register via `init()`.
Create a new file in `internal/modules/`:

```go
package modules

import (
	"context"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

type myModule struct{}

func init() { engine.Register(myModule{}) }

func (myModule) Name() string          { return "my_module" }
func (myModule) Description() string    { return "One-line description shown in the UI." }
func (myModule) Category() string       { return "recon" } // recon|passive|semi-offensive|intel|analysis
func (myModule) Dependencies() []string { return nil }     // names of modules that must run first
func (myModule) RequiredKey() string    { return "" }      // env var name, or "" for keyless
func (myModule) RateLimitRPM() int      { return 0 }

func (myModule) Run(ctx context.Context, target safety.Target, deps *engine.SharedState,
	cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	// ... do the work; ALWAYS fetch through `client` (it carries the SSRF guard) ...
	return map[string]any{
		"some_field":       "value",
		"findings":         []map[string]any{},   // optional: severity-bearing items
		"overall_severity": "info",                // optional: drives the risk score
	}, nil
}
```

Guidelines:
- **Always** make outbound requests through the provided `*httpx.Client` (or
  `safety.NewDialer`) so the SSRF guard cannot be bypassed.
- For findings the risk scorer/exporters can pick up, emit a `findings` array of
  `{name, severity, description, url}` and/or an `overall_severity` field.
- If the module needs an API key, return its env-var name from `RequiredKey()`. The
  engine will **skip** the module gracefully when the key is absent — never panic or
  hard-fail on a missing key.
- Respect `ctx` (cancellation/timeout) and bound any concurrency.
- Recover gracefully from upstream errors (return a result with a note rather than an
  error where the original tool would degrade).
- Keep network access keyless wherever possible — keyless modules are the project's
  priority.

Add a table-driven test where practical (use `net/http/httptest` for HTTP modules).

## Commit & PR workflow

1. Fork and branch from `main`.
2. Keep commits focused; write clear messages.
3. Ensure `gofmt`, `go vet`, `go test -race`, and `go build` are clean.
4. Open a PR against <https://github.com/secuity-life-org/Obscura>; describe the change
   and include sample output for new modules.
5. For security-sensitive changes, see [SECURITY.md](SECURITY.md).

## Reporting bugs / requesting features

Open an issue: <https://github.com/secuity-life-org/Obscura/issues>. Include the
version (`obscura --version`), steps to reproduce, and (sanitized) output.
