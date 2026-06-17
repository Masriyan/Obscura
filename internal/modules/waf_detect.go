package modules

import (
	"context"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// wafDetectModule detects WAF/CDN products from response headers (name
// "waf_detect"), porting the WAF_SIGNATURES table from aegis.py.
type wafDetectModule struct{}

func init() { engine.Register(wafDetectModule{}) }

func (wafDetectModule) Name() string { return "waf_detect" }
func (wafDetectModule) Description() string {
	return "WAF/CDN detection from response headers (Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, ...)."
}
func (wafDetectModule) Category() string       { return "recon" }
func (wafDetectModule) Dependencies() []string { return nil }
func (wafDetectModule) RequiredKey() string    { return "" }
func (wafDetectModule) RateLimitRPM() int      { return 0 }

var wafSignatures = []struct {
	name string
	sigs []string
}{
	{"Cloudflare", []string{"cf-ray", "cf-cache-status", "__cfduid", "cloudflare"}},
	{"AWS WAF", []string{"x-amzn-requestid", "x-amz-cf-id", "awselb"}},
	{"Akamai", []string{"akamai-origin-hop", "x-akamai-transformed"}},
	{"Imperva/Incapsula", []string{"x-iinfo", "incap_ses", "visid_incap"}},
	{"Sucuri", []string{"x-sucuri-id", "x-sucuri-cache"}},
	{"ModSecurity", []string{"mod_security", "modsecurity"}},
	{"F5 BIG-IP", []string{"x-wa-info", "bigipserver"}},
	{"Barracuda", []string{"barra_counter_session"}},
	{"Fortinet FortiWeb", []string{"fortiwafsid"}},
	{"DDoS-Guard", []string{"ddos-guard"}},
}

func (wafDetectModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	resp, err := client.Get(ctx, target.URL)
	if err != nil {
		return map[string]any{"error": err.Error(), "target": target.URL}, nil
	}
	resp.Body.Close()

	// Build a lowercased haystack of header names + values + set-cookie.
	var b strings.Builder
	for name, vals := range resp.Header {
		b.WriteString(strings.ToLower(name))
		b.WriteByte(' ')
		for _, v := range vals {
			b.WriteString(strings.ToLower(v))
			b.WriteByte(' ')
		}
	}
	haystack := b.String()

	var detected []string
	for _, waf := range wafSignatures {
		for _, sig := range waf.sigs {
			if strings.Contains(haystack, sig) {
				detected = append(detected, waf.name)
				break
			}
		}
	}

	return map[string]any{
		"target":        target.URL,
		"waf_detected":  len(detected) > 0,
		"products":      detected,
		"server_header": resp.Header.Get("Server"),
	}, nil
}
