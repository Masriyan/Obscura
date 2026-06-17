package modules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// subdomainPermutationModule ports modules/subdomain_permutation.py: generates
// smart mutations from discovered subdomains (depends on subdomain_scan) and
// resolves the candidates to find hidden assets.
type subdomainPermutationModule struct{}

func init() { engine.Register(subdomainPermutationModule{}) }

func (subdomainPermutationModule) Name() string { return "subdomain_permutation" }
func (subdomainPermutationModule) Description() string {
	return "Smart subdomain mutation engine — generates permutations from discovered subdomains to find hidden assets."
}
func (subdomainPermutationModule) Category() string       { return "recon" }
func (subdomainPermutationModule) Dependencies() []string { return []string{"subdomain_scan"} }
func (subdomainPermutationModule) RequiredKey() string    { return "" }
func (subdomainPermutationModule) RateLimitRPM() int      { return 200 }

var permWords = []string{
	"dev", "staging", "stage", "stg", "prod", "production", "test", "qa", "uat", "sandbox",
	"internal", "private", "corp", "vpn", "admin", "panel", "dashboard", "api", "api2", "apiv2",
	"app", "web", "www2", "portal", "mail", "smtp", "ftp", "db", "database", "redis", "mongo",
	"cdn", "static", "assets", "media", "backup", "old", "legacy", "ci", "cd", "jenkins", "gitlab",
	"docker", "k8s", "kube", "monitor", "grafana", "kibana", "auth", "sso", "login", "new", "beta", "v2",
}

func (subdomainPermutationModule) Run(ctx context.Context, target safety.Target, deps *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host

	existing := map[string]bool{}
	if data, ok := deps.Get("subdomain_scan"); ok {
		if found, ok := data["found"].([]any); ok {
			for _, f := range found {
				if m, ok := f.(map[string]any); ok {
					if s, _ := m["subdomain"].(string); s != "" {
						existing[strings.ToLower(s)] = true
					}
				}
			}
		}
	}

	candidates := map[string]bool{}
	addCandidate := func(c string) {
		if validSub(c, domain) && !existing[c] {
			candidates[c] = true
		}
	}

	if len(existing) == 0 {
		// No known subs: permute base words against the apex.
		for _, w := range permWords {
			addCandidate(w + "." + domain)
		}
	} else {
		for sub := range existing {
			prefix := strings.TrimSuffix(sub, "."+domain)
			if prefix == "" || prefix == sub {
				continue
			}
			for _, w := range permWords {
				addCandidate(w + "." + prefix + "." + domain)
				addCandidate(prefix + "-" + w + "." + domain)
				addCandidate(w + "-" + prefix + "." + domain)
			}
			for n := 1; n <= 5; n++ {
				addCandidate(fmt.Sprintf("%s%d.%s", prefix, n, domain))
			}
		}
	}

	cands := keysOf(candidates)
	sort.Strings(cands)
	if len(cands) > 500 {
		cands = cands[:500]
	}

	var found []any
	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		if ips := lookupA(ctx, c); len(ips) > 0 {
			found = append(found, map[string]any{"subdomain": c, "ips": ips, "source": "permutation"})
		}
	}

	res := map[string]any{
		"domain":                 domain,
		"existing_subdomains":    len(existing),
		"permutations_generated": len(cands),
		"new_subdomains":         found,
		"total_found":            len(found),
	}
	if len(found) > 0 {
		res["risk_assessment"] = fmt.Sprintf("Discovered %d additional subdomains through permutation — review for shadow IT.", len(found))
	} else {
		res["risk_assessment"] = "No additional subdomains found through permutation."
	}
	return res, nil
}

func validSub(candidate, domain string) bool {
	if !strings.HasSuffix(candidate, "."+domain) || strings.Contains(candidate, "..") {
		return false
	}
	prefix := strings.TrimSuffix(candidate, "."+domain)
	if prefix == "" || len(prefix) > 63 || strings.HasPrefix(prefix, "-") || strings.HasSuffix(prefix, "-") {
		return false
	}
	return true
}
