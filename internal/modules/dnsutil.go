package modules

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// lookupTXT returns the TXT record strings for name.
func lookupTXT(ctx context.Context, name string) []string {
	return queryStrings(ctx, name, dns.TypeTXT)
}

// lookupA returns the A-record IPs for name.
func lookupA(ctx context.Context, name string) []string {
	return queryStrings(ctx, name, dns.TypeA)
}

// lookupCNAME returns the CNAME target for name (without trailing dot), or "".
func lookupCNAME(ctx context.Context, name string) string {
	c := &dns.Client{Timeout: 4 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeCNAME)
	m.RecursionDesired = true
	resp, _, err := c.ExchangeContext(ctx, m, resolverAddr())
	if err != nil || resp == nil {
		return ""
	}
	for _, rr := range resp.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			return strings.TrimSuffix(cn.Target, ".")
		}
	}
	return ""
}

// lookupCAA returns CAA record values for name.
func lookupCAA(ctx context.Context, name string) []string {
	c := &dns.Client{Timeout: 4 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeCAA)
	m.RecursionDesired = true
	resp, _, err := c.ExchangeContext(ctx, m, resolverAddr())
	if err != nil || resp == nil {
		return nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			out = append(out, caa.Tag+" "+caa.Value)
		}
	}
	return out
}

// hasDNSKEY reports whether the zone publishes DNSSEC keys.
func hasDNSKEY(ctx context.Context, name string) bool {
	c := &dns.Client{Timeout: 4 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeDNSKEY)
	m.RecursionDesired = true
	resp, _, err := c.ExchangeContext(ctx, m, resolverAddr())
	if err != nil || resp == nil {
		return false
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			return true
		}
	}
	return false
}

// queryStrings runs a DNS query and returns the record-value tail of each answer.
func queryStrings(ctx context.Context, name string, qtype uint16) []string {
	c := &dns.Client{Timeout: 4 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	resp, _, err := c.ExchangeContext(ctx, m, resolverAddr())
	if err != nil || resp == nil {
		return nil
	}
	out := make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.TXT:
			out = append(out, strings.Join(v.Txt, ""))
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		default:
			out = append(out, rrText(rr))
		}
	}
	return out
}
