package modules

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// zoneTransferModule ports modules/dns_zone_transfer.py (name "dns_zone_transfer"):
// attempts AXFR against each nameserver — a successful transfer is critical.
type zoneTransferModule struct{}

func init() { engine.Register(zoneTransferModule{}) }

func (zoneTransferModule) Name() string { return "dns_zone_transfer" }
func (zoneTransferModule) Description() string {
	return "Tests for DNS zone transfer (AXFR) misconfiguration — reveals entire DNS zone if vulnerable."
}
func (zoneTransferModule) Category() string       { return "recon" }
func (zoneTransferModule) Dependencies() []string { return nil }
func (zoneTransferModule) RequiredKey() string    { return "" }
func (zoneTransferModule) RateLimitRPM() int      { return 0 }

func (zoneTransferModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	res := map[string]any{
		"domain": domain, "nameservers": []string{}, "vulnerable": false,
		"zone_records": []any{}, "total_records": 0, "tested_ns": 0, "vulnerable_ns": []string{},
	}

	nameservers := getNameservers(ctx, domain)
	res["nameservers"] = nameservers
	if len(nameservers) == 0 {
		res["error"] = "Could not resolve nameservers"
		return res, nil
	}

	seen := map[string]bool{}
	var records []any
	var vulnNS []string
	tested := 0
	for _, ns := range nameservers {
		if ctx.Err() != nil {
			break
		}
		tested++
		recs := tryAXFR(domain, ns)
		if len(recs) > 0 {
			vulnNS = append(vulnNS, ns)
			for _, r := range recs {
				m := r.(map[string]any)
				key := fmt.Sprintf("%v|%v|%v", m["name"], m["type"], m["value"])
				if !seen[key] {
					seen[key] = true
					records = append(records, r)
				}
			}
		}
	}

	if len(records) > 500 {
		records = records[:500]
	}
	res["tested_ns"] = tested
	res["vulnerable"] = len(vulnNS) > 0
	res["vulnerable_ns"] = vulnNS
	res["zone_records"] = records
	res["total_records"] = len(records)
	if len(vulnNS) > 0 {
		res["severity"] = "critical"
		res["risk_assessment"] = fmt.Sprintf("CRITICAL: Zone transfer succeeded on %d nameserver(s). Entire DNS zone (%d records) is exposed.", len(vulnNS), len(records))
	} else {
		res["severity"] = "info"
		res["risk_assessment"] = "Zone transfer properly restricted on all nameservers."
	}
	return res, nil
}

func getNameservers(ctx context.Context, domain string) []string {
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	resp, _, err := c.ExchangeContext(ctx, m, resolverAddr())
	if err != nil || resp == nil {
		return nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, trimDot(ns.Ns))
		}
	}
	return out
}

func tryAXFR(domain, nameserver string) []any {
	t := new(dns.Transfer)
	t.DialTimeout = 10 * time.Second
	t.ReadTimeout = 15 * time.Second
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	ch, err := t.In(m, net.JoinHostPort(nameserver, "53"))
	if err != nil {
		return nil
	}
	var records []any
	for env := range ch {
		if env.Error != nil {
			return nil // refused/timeout — expected/good
		}
		for _, rr := range env.RR {
			h := rr.Header()
			records = append(records, map[string]any{
				"name":  trimDot(h.Name),
				"type":  dns.TypeToString[h.Rrtype],
				"ttl":   h.Ttl,
				"value": rrText(rr),
			})
		}
	}
	return records
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
