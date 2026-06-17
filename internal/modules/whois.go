package modules

import (
	"context"

	whois "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// whoisModule ports modules/whois_lookup.py (name "whois"): registration data.
type whoisModule struct{}

func init() { engine.Register(whoisModule{}) }

func (whoisModule) Name() string { return "whois" }
func (whoisModule) Description() string {
	return "WHOIS registration lookup (registrar, dates, registrant, nameservers)."
}
func (whoisModule) Category() string       { return "recon" }
func (whoisModule) Dependencies() []string { return nil }
func (whoisModule) RequiredKey() string    { return "" }
func (whoisModule) RateLimitRPM() int      { return 0 }

func (whoisModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	raw, err := whois.Whois(domain)
	if err != nil {
		return map[string]any{"error": err.Error(), "domain": domain}, nil
	}
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		// Still return the raw text so the analyst has something.
		return map[string]any{"domain": domain, "raw": truncate(raw, 4000)}, nil
	}

	out := map[string]any{"domain": domain}
	if parsed.Domain != nil {
		out["created_date"] = parsed.Domain.CreatedDate
		out["updated_date"] = parsed.Domain.UpdatedDate
		out["expiration_date"] = parsed.Domain.ExpirationDate
		out["name_servers"] = parsed.Domain.NameServers
		out["status"] = parsed.Domain.Status
		out["dnssec"] = parsed.Domain.DNSSec
	}
	if parsed.Registrar != nil {
		out["registrar"] = parsed.Registrar.Name
	}
	if parsed.Registrant != nil {
		out["registrant"] = map[string]any{
			"organization": parsed.Registrant.Organization,
			"country":      parsed.Registrant.Country,
			"name":         parsed.Registrant.Name,
		}
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
