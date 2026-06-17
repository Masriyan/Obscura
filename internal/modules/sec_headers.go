package modules

import (
	"context"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// secHeadersModule analyzes HTTP security headers (name "sec_headers"). Each row
// reports a header's presence; the missing count feeds the scan risk summary.
type secHeadersModule struct{}

func init() { engine.Register(secHeadersModule{}) }

func (secHeadersModule) Name() string { return "sec_headers" }
func (secHeadersModule) Description() string {
	return "HTTP security header analysis — flags missing CSP, HSTS, X-Frame-Options, and friends."
}
func (secHeadersModule) Category() string       { return "passive" }
func (secHeadersModule) Dependencies() []string { return nil }
func (secHeadersModule) RequiredKey() string    { return "" }
func (secHeadersModule) RateLimitRPM() int      { return 0 }

var securityHeaders = []struct {
	name, severity, advice string
}{
	{"Content-Security-Policy", "high", "Implement CSP to mitigate XSS and data injection."},
	{"Strict-Transport-Security", "high", "Add HSTS (max-age>=31536000; includeSubDomains)."},
	{"X-Frame-Options", "medium", "Set to DENY/SAMEORIGIN to prevent clickjacking."},
	{"X-Content-Type-Options", "medium", "Set to nosniff to stop MIME sniffing."},
	{"Referrer-Policy", "low", "Set a Referrer-Policy to limit referrer leakage."},
	{"Permissions-Policy", "low", "Restrict powerful browser features."},
}

func (secHeadersModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	resp, err := client.Get(ctx, target.URL)
	if err != nil {
		return map[string]any{"error": err.Error(), "target": target.URL}, nil
	}
	resp.Body.Close()
	hdr := resp.Header

	rows := make([]map[string]any, 0, len(securityHeaders))
	findings := make([]map[string]any, 0)
	missing := 0
	for _, h := range securityHeaders {
		val := hdr.Get(h.name)
		status := "OK"
		if strings.TrimSpace(val) == "" {
			status = "Missing"
			missing++
			findings = append(findings, map[string]any{
				"name": "Missing " + h.name, "severity": h.severity, "description": h.advice,
			})
		}
		rows = append(rows, map[string]any{
			"header": h.name, "status": status, "value": val, "severity": h.severity,
		})
	}

	overall := "info"
	switch {
	case missing >= 4:
		overall = "high"
	case missing >= 2:
		overall = "medium"
	case missing >= 1:
		overall = "low"
	}

	return map[string]any{
		"target":              target.URL,
		"status_code":         resp.StatusCode,
		"server":              resp.Header.Get("Server"),
		"rows":                rows,
		"findings":            findings,
		"missing_sec_headers": missing,
		"present":             len(securityHeaders) - missing,
		"total_checked":       len(securityHeaders),
		"overall_severity":    overall,
	}, nil
}
