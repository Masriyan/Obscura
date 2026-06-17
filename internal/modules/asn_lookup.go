package modules

import (
	"context"
	"net"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// asnLookupModule resolves ASN/BGP info via Team Cymru's DNS-based service
// (name "asn_lookup") — keyless, no API: query <reversed-ip>.origin.asn.cymru.com.
type asnLookupModule struct{}

func init() { engine.Register(asnLookupModule{}) }

func (asnLookupModule) Name() string { return "asn_lookup" }
func (asnLookupModule) Description() string {
	return "Resolves ASN, BGP prefix, and network owner via Team Cymru's DNS service (no API key)."
}
func (asnLookupModule) Category() string       { return "intel" }
func (asnLookupModule) Dependencies() []string { return nil }
func (asnLookupModule) RequiredKey() string    { return "" }
func (asnLookupModule) RateLimitRPM() int      { return 0 }

func (asnLookupModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	ip := resolveOneIP(target.Host)
	if ip == "" {
		return map[string]any{"error": "could not resolve a public IPv4 for " + target.Host}, nil
	}
	parsed := net.ParseIP(ip)
	if parsed.To4() == nil {
		return map[string]any{"ip": ip, "note": "ASN lookup supports IPv4 only"}, nil
	}

	// origin: query <reversed-ip>.origin.asn.cymru.com -> "ASN | Prefix | CC | Registry | Allocated"
	rev := reverseIPv4(ip)
	origin := firstTXTAny(ctx, rev+".origin.asn.cymru.com")
	res := map[string]any{"ip": ip}
	if origin == "" {
		res["note"] = "No Team Cymru data for this IP"
		return res, nil
	}
	of := splitCymru(origin)
	asn := of[0]
	res["asn"] = "AS" + asn
	res["bgp_prefix"] = of[1]
	res["country"] = of[2]
	res["registry"] = of[3]
	res["allocated"] = of[4]

	// AS name: query AS<asn>.asn.cymru.com -> "ASN | CC | Registry | Allocated | AS Name"
	if asn != "" {
		if name := firstTXTAny(ctx, "AS"+asn+".asn.cymru.com"); name != "" {
			nf := splitCymru(name)
			res["as_name"] = nf[len(nf)-1]
		}
	}
	return res, nil
}

func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

// splitCymru splits a "a | b | c" record into trimmed fields, padded to 5.
func splitCymru(s string) []string {
	raw := strings.Split(s, "|")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, strings.TrimSpace(p))
	}
	for len(out) < 5 {
		out = append(out, "")
	}
	return out
}

// firstTXTAny returns the first TXT record for name (any content).
func firstTXTAny(ctx context.Context, name string) string {
	for _, txt := range lookupTXT(ctx, name) {
		if strings.TrimSpace(txt) != "" {
			return txt
		}
	}
	return ""
}
