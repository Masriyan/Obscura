package modules

import (
	"context"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// spfModule ports modules/spf_analyzer.py (name "spf_analyzer"): flattens SPF
// include chains, counts DNS lookups, checks DMARC, grades the policy.
type spfModule struct{}

func init() { engine.Register(spfModule{}) }

func (spfModule) Name() string { return "spf_analyzer" }
func (spfModule) Description() string {
	return "Deep SPF record analysis — flattens include chains, counts DNS lookups, detects mail spoofing risk."
}
func (spfModule) Category() string       { return "recon" }
func (spfModule) Dependencies() []string { return nil }
func (spfModule) RequiredKey() string    { return "" }
func (spfModule) RateLimitRPM() int      { return 0 }

const spfMaxRecursion = 10

func (spfModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	res := map[string]any{
		"domain": domain, "spf_record": nil, "has_spf": false,
		"lookup_count": 0, "max_lookups": 10, "exceeds_limit": false,
		"policy": nil, "all_includes": []any{}, "authorized_ips": []string{},
		"authorized_networks": []string{}, "issues": []string{}, "score": 0, "grade": "F",
	}
	issues := []string{}

	spf := getSPF(ctx, domain)
	if spf == "" {
		res["issues"] = append(issues, "No SPF record found — domain is vulnerable to email spoofing")
		return res, nil
	}
	res["spf_record"] = spf
	res["has_spf"] = true

	visited := map[string]bool{}
	includes := []any{}
	ips := []string{}
	networks := []string{}
	count := 0
	flattenSPF(ctx, domain, spf, visited, &includes, &ips, &networks, &count, 0)

	res["lookup_count"] = count
	res["exceeds_limit"] = count > 10
	res["all_includes"] = includes
	res["authorized_ips"] = capStrings(ips, 100)
	res["authorized_networks"] = capStrings(networks, 100)

	score := 0
	switch {
	case strings.Contains(spf, "+all"):
		res["policy"] = "pass_all"
		issues = append(issues, "CRITICAL: SPF uses +all (pass all) — anyone can spoof emails from this domain")
	case strings.Contains(spf, "~all"):
		res["policy"] = "softfail"
		issues = append(issues, "SPF uses ~all (softfail) — spoofed emails may still be delivered")
		score += 40
	case strings.Contains(spf, "-all"):
		res["policy"] = "hardfail"
		score += 60
	case strings.Contains(spf, "?all"):
		res["policy"] = "neutral"
		issues = append(issues, "SPF uses ?all (neutral) — provides no protection against spoofing")
	default:
		res["policy"] = "implicit_pass"
		issues = append(issues, "SPF has no 'all' mechanism — defaults to pass")
	}

	if count > 10 {
		issues = append(issues, "SPF exceeds 10 DNS lookup limit — causes PermError on receiving mail servers, effectively breaking SPF")
	} else {
		score += 20
	}
	if strings.Contains(strings.ToLower(spf), "ptr") {
		issues = append(issues, "SPF uses deprecated 'ptr' mechanism — slow and unreliable")
	}
	if len(includes) > 5 {
		issues = append(issues, "Complex SPF with many includes — consider flattening")
	}

	dmarc := checkDMARC(ctx, domain)
	res["dmarc"] = dmarc
	if found, _ := dmarc["found"].(bool); found {
		score += 20
		if dmarc["policy"] == "reject" {
			score += 10
		}
	}

	res["score"] = score
	res["grade"] = spfGrade(score)
	res["issues"] = issues
	return res, nil
}

func getSPF(ctx context.Context, domain string) string {
	for _, txt := range lookupTXT(ctx, domain) {
		if strings.HasPrefix(txt, "v=spf1") {
			return txt
		}
	}
	return ""
}

func flattenSPF(ctx context.Context, domain, spf string, visited map[string]bool, includes *[]any, ips, networks *[]string, count *int, depth int) {
	if depth > spfMaxRecursion || visited[domain] {
		return
	}
	visited[domain] = true
	for _, part := range strings.Fields(spf) {
		mech := strings.TrimLeft(part, "+-~?")
		switch {
		case strings.HasPrefix(mech, "include:"):
			tgt := strings.SplitN(mech, ":", 2)[1]
			*count++
			*includes = append(*includes, map[string]any{"domain": tgt, "depth": depth, "from": domain})
			if sub := getSPF(ctx, tgt); sub != "" {
				flattenSPF(ctx, tgt, sub, visited, includes, ips, networks, count, depth+1)
			}
		case strings.HasPrefix(mech, "redirect="):
			tgt := strings.SplitN(mech, "=", 2)[1]
			*count++
			*includes = append(*includes, map[string]any{"domain": tgt, "depth": depth, "from": domain, "type": "redirect"})
			if sub := getSPF(ctx, tgt); sub != "" {
				flattenSPF(ctx, tgt, sub, visited, includes, ips, networks, count, depth+1)
			}
		case strings.HasPrefix(mech, "a"), strings.HasPrefix(mech, "mx"), strings.HasPrefix(mech, "exists:"):
			*count++
		case strings.HasPrefix(mech, "ip4:"):
			addr := strings.SplitN(mech, ":", 2)[1]
			if strings.Contains(addr, "/") {
				*networks = append(*networks, addr)
			} else {
				*ips = append(*ips, addr)
			}
		case strings.HasPrefix(mech, "ip6:"):
			*networks = append(*networks, strings.SplitN(mech, ":", 2)[1])
		}
	}
}

func checkDMARC(ctx context.Context, domain string) map[string]any {
	for _, txt := range lookupTXT(ctx, "_dmarc."+domain) {
		if strings.Contains(txt, "v=DMARC1") {
			policy := "none"
			switch {
			case strings.Contains(txt, "p=reject"):
				policy = "reject"
			case strings.Contains(txt, "p=quarantine"):
				policy = "quarantine"
			}
			return map[string]any{"found": true, "record": txt, "policy": policy}
		}
	}
	return map[string]any{"found": false}
}

func spfGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 70:
		return "B"
	case score >= 50:
		return "C"
	case score >= 30:
		return "D"
	default:
		return "F"
	}
}

func capStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
