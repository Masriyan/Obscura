package modules

import (
	"context"
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

//go:embed data/subdomains.txt
var subdomainWordlist string

// dnsBruteforceModule actively enumerates subdomains from an embedded wordlist
// (name "dns_bruteforce") — fully offline subdomain discovery, no crt.sh.
type dnsBruteforceModule struct{}

func init() { engine.Register(dnsBruteforceModule{}) }

func (dnsBruteforceModule) Name() string { return "dns_bruteforce" }
func (dnsBruteforceModule) Description() string {
	return "Active subdomain brute-force from a built-in wordlist (offline; with wildcard detection)."
}
func (dnsBruteforceModule) Category() string       { return "recon" }
func (dnsBruteforceModule) Dependencies() []string { return nil }
func (dnsBruteforceModule) RequiredKey() string    { return "" }
func (dnsBruteforceModule) RateLimitRPM() int      { return 0 }

func wordlist() []string {
	var out []string
	for _, line := range strings.Split(subdomainWordlist, "\n") {
		if w := strings.TrimSpace(line); w != "" {
			out = append(out, w)
		}
	}
	return out
}

func (dnsBruteforceModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	words := wordlist()

	// Wildcard detection: if a random label resolves, the zone is a catch-all.
	wildcard := len(lookupA(ctx, "obx-nonexistent-9z7q3."+domain)) > 0

	var (
		mu    sync.Mutex
		found []map[string]any
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 30)
	)
	for _, w := range words {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sub := w + "." + domain
			if ips := lookupA(ctx, sub); len(ips) > 0 {
				mu.Lock()
				found = append(found, map[string]any{"subdomain": sub, "ips": ips})
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool { return found[i]["subdomain"].(string) < found[j]["subdomain"].(string) })

	res := map[string]any{
		"domain":      domain,
		"wordlist":    len(words),
		"wildcard":    wildcard,
		"found":       found,
		"total_found": len(found),
	}
	if wildcard {
		res["note"] = "Wildcard DNS detected — brute-force results may be unreliable (catch-all)."
		res["findings"] = []map[string]any{{
			"name": "Wildcard DNS", "severity": "low",
			"description": "Domain resolves arbitrary subdomains (catch-all), which can mask takeovers.",
		}}
		res["overall_severity"] = "low"
	}
	if len(found) > 0 && !wildcard {
		res["risk_assessment"] = fmt.Sprintf("Discovered %d live subdomains via brute-force.", len(found))
	}
	return res, nil
}
