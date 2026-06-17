package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// dnsModule ports modules/dns_lookup.py (name "dns_records"): A/AAAA/MX/NS/TXT/SOA.
type dnsModule struct{}

func init() { engine.Register(dnsModule{}) }

func (dnsModule) Name() string { return "dns_records" }
func (dnsModule) Description() string {
	return "Comprehensive DNS record lookup (A, AAAA, MX, NS, TXT, SOA)."
}
func (dnsModule) Category() string       { return "recon" }
func (dnsModule) Dependencies() []string { return nil }
func (dnsModule) RequiredKey() string    { return "" }
func (dnsModule) RateLimitRPM() int      { return 0 }

var dnsRecordTypes = []struct {
	name  string
	qtype uint16
}{
	{"A", dns.TypeA},
	{"AAAA", dns.TypeAAAA},
	{"MX", dns.TypeMX},
	{"NS", dns.TypeNS},
	{"TXT", dns.TypeTXT},
	{"SOA", dns.TypeSOA},
}

func (dnsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	if domain == "" {
		return nil, fmt.Errorf("no host in target")
	}

	server := resolverAddr()
	c := &dns.Client{Timeout: 5 * time.Second}
	out := make(map[string]any, len(dnsRecordTypes))

	for _, rt := range dnsRecordTypes {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), rt.qtype)
		m.RecursionDesired = true

		resp, _, err := c.ExchangeContext(ctx, m, server)
		if err != nil {
			out[rt.name] = []string{}
			continue
		}
		recs := make([]string, 0, len(resp.Answer))
		for _, ans := range resp.Answer {
			recs = append(recs, rrText(ans))
		}
		out[rt.name] = recs
		if resp.Rcode == dns.RcodeNameError { // NXDOMAIN — stop early like the original
			break
		}
	}
	return out, nil
}

// rrText renders a resource record's value without the leading header columns,
// approximating dnspython's to_text() for the record value.
func rrText(rr dns.RR) string {
	full := rr.String()
	// dns.RR.String() => "name\tttl\tclass\ttype\tdata"; keep the data tail.
	parts := strings.SplitN(full, "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return full
}

// resolverAddr returns the configured system resolver, or a public default.
func resolverAddr() string {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(conf.Servers) > 0 {
		return conf.Servers[0] + ":" + conf.Port
	}
	return "1.1.1.1:53"
}
