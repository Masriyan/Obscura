package modules

import (
	"context"
	"io"
	"net"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// reverseIPModule ports modules/reverse_ip.py (name "reverse_ip"): finds other
// domains on the same IP via HackerTarget (free, no key).
type reverseIPModule struct{}

func init() { engine.Register(reverseIPModule{}) }

func (reverseIPModule) Name() string { return "reverse_ip" }
func (reverseIPModule) Description() string {
	return "Finds all domains hosted on the same IP — reveals shared hosting, co-tenants, and lateral targets."
}
func (reverseIPModule) Category() string       { return "recon" }
func (reverseIPModule) Dependencies() []string { return nil }
func (reverseIPModule) RequiredKey() string    { return "" }
func (reverseIPModule) RateLimitRPM() int      { return 30 }

func (reverseIPModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	domain := target.Host
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return map[string]any{"error": "Could not resolve " + domain, "domains": []any{}, "ip": nil}, nil
	}
	ip := ips[0]

	res := map[string]any{
		"ip": ip, "target_domain": domain, "domains": []string{}, "total_found": 0,
		"shared_hosting": false, "risk_assessment": "Low", "hosting_provider": nil,
	}

	resp, err := client.Get(ctx, "https://api.hackertarget.com/reverseiplookup/?q="+ip)
	domains := []string{}
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			text := string(body)
			if !strings.Contains(strings.ToLower(text), "error") && !strings.Contains(strings.ToLower(text), "api count") {
				seen := map[string]bool{}
				for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
					d := strings.ToLower(strings.TrimSpace(line))
					if d != "" && d != strings.ToLower(domain) && strings.Contains(d, ".") && len(d) > 3 && !seen[d] {
						seen[d] = true
						domains = append(domains, d)
					}
				}
			}
		}
	}
	if len(domains) > 100 {
		domains = domains[:100]
	}
	res["domains"] = domains
	res["total_found"] = len(domains)
	res["shared_hosting"] = len(domains) > 1

	switch {
	case len(domains) > 20:
		res["risk_assessment"] = "High — Shared hosting with many co-tenants increases lateral attack risk"
	case len(domains) > 5:
		res["risk_assessment"] = "Medium — Multiple domains on same IP suggest shared hosting"
	case len(domains) > 0:
		res["risk_assessment"] = "Low — Few co-tenant domains"
	default:
		res["risk_assessment"] = "Info — Appears to be dedicated hosting"
	}
	return res, nil
}
