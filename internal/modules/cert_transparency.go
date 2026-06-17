package modules

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// certTransparencyModule ports modules/certificate_transparency.py (name
// "cert_transparency"): queries crt.sh for certificate history.
type certTransparencyModule struct{}

func init() { engine.Register(certTransparencyModule{}) }

func (certTransparencyModule) Name() string { return "cert_transparency" }
func (certTransparencyModule) Description() string {
	return "Query crt.sh for certificate history, spotting wildcard certs and recent issuances."
}
func (certTransparencyModule) Category() string       { return "recon" }
func (certTransparencyModule) Dependencies() []string { return nil }
func (certTransparencyModule) RequiredKey() string    { return "" }
func (certTransparencyModule) RateLimitRPM() int      { return 0 }

type crtEntry struct {
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
}

func (certTransparencyModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	domain := target.Host
	resp, err := client.Get(ctx, "https://crt.sh/?q="+domain+"&output=json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var certs []crtEntry
	if err := json.Unmarshal(body, &certs); err != nil || len(certs) == 0 {
		return nil, nil // skipped (matches "return None" on empty/parse error)
	}

	issuers := map[string]bool{}
	flags := []string{}
	wildcard, recent := false, false
	now := time.Now()
	for _, c := range certs {
		if strings.Contains(c.NameValue, "*.") && !wildcard {
			wildcard = true
			flags = append(flags, "Wildcard Certificate Detected (Subdomain Sprawl Risk)")
		}
		if c.IssuerName != "" {
			issuers[c.IssuerName] = true
		}
		if c.NotBefore != "" {
			raw := strings.SplitN(c.NotBefore, ".", 2)[0]
			if t, err := time.Parse("2006-01-02T15:04:05", raw); err == nil {
				if d := now.Sub(t); d >= 0 && d < 7*24*time.Hour && !recent {
					recent = true
					flags = append(flags, "Recent Certificate Issuance (< 7 days) - Possible Phishing")
				}
			}
		}
	}
	reuse := false
	if len(issuers) > 3 {
		reuse = true
		flags = append(flags, "Multiple Certificate Authorities detected - Possible infrastructure sharing.")
	}

	top := certs
	if len(top) > 20 {
		top = top[:20]
	}
	return map[string]any{
		"total_certificates_found": len(certs),
		"certificates":             top,
		"analysis": map[string]any{
			"wildcard_certs_found": wildcard,
			"recent_issuance":      recent,
			"cert_reuse":           reuse,
			"unique_issuers":       keys(issuers),
			"flags":                flags,
		},
	}, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
