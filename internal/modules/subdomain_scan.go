package modules

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// subdomainScanModule provides passive subdomain enumeration via crt.sh
// certificate transparency data (name "subdomain_scan"). It resolves each
// candidate and reports the live ones. Other modules depend on its output.
type subdomainScanModule struct{}

func init() { engine.Register(subdomainScanModule{}) }

func (subdomainScanModule) Name() string { return "subdomain_scan" }
func (subdomainScanModule) Description() string {
	return "Passive subdomain enumeration from certificate transparency (crt.sh), with DNS resolution."
}
func (subdomainScanModule) Category() string       { return "recon" }
func (subdomainScanModule) Dependencies() []string { return nil }
func (subdomainScanModule) RequiredKey() string    { return "" }
func (subdomainScanModule) RateLimitRPM() int      { return 0 }

func (subdomainScanModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	domain := target.Host
	resp, err := client.Get(ctx, "https://crt.sh/?q=%25."+domain+"&output=json")
	if err != nil {
		// crt.sh frequently 502s on heavy wildcard queries — degrade to an
		// empty result (matches the Python helper returning []) instead of
		// failing the whole module.
		return map[string]any{"domain": domain, "found": []any{}, "total": 0, "candidates": 0, "note": "crt.sh unavailable: " + err.Error()}, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return map[string]any{"domain": domain, "found": []any{}, "total": 0, "candidates": 0}, nil
	}
	var certs []crtEntry
	if err := json.Unmarshal(body, &certs); err != nil {
		return map[string]any{"domain": domain, "found": []any{}, "total": 0, "candidates": 0}, nil
	}

	// Collect unique candidate names.
	set := map[string]bool{}
	for _, c := range certs {
		for _, name := range strings.Split(c.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" && strings.HasSuffix(name, domain) {
				set[name] = true
			}
		}
	}
	candidates := keys(set)
	sort.Strings(candidates)
	if len(candidates) > 300 { // cap resolution work
		candidates = candidates[:300]
	}

	found := []any{}
	for _, sub := range candidates {
		if ctx.Err() != nil {
			break
		}
		ips := lookupA(ctx, sub)
		if len(ips) > 0 {
			found = append(found, map[string]any{"subdomain": sub, "ips": ips, "source": "crt.sh"})
		}
	}

	return map[string]any{
		"domain":     domain,
		"found":      found,
		"total":      len(found),
		"candidates": len(candidates),
	}, nil
}
