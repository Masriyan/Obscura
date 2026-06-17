package modules

import (
	"context"
	"io"
	"net/http"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// This file ports several small keyless web-posture checks from aegis.py:
// robots_txt, security_txt, http_methods, cors, cookie_audit.

// --- robots.txt ---

type robotsTxtModule struct{}

func init() { engine.Register(robotsTxtModule{}) }

func (robotsTxtModule) Name() string { return "robots_txt" }
func (robotsTxtModule) Description() string {
	return "Fetches robots.txt and surfaces disallowed paths (often interesting/sensitive)."
}
func (robotsTxtModule) Category() string       { return "recon" }
func (robotsTxtModule) Dependencies() []string { return nil }
func (robotsTxtModule) RequiredKey() string    { return "" }
func (robotsTxtModule) RateLimitRPM() int      { return 0 }

func (robotsTxtModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	body, status, _ := fetchText(ctx, client, strings.TrimRight(target.URL, "/")+"/robots.txt")
	if status != 200 || body == "" {
		return map[string]any{"present": false, "status_code": status}, nil
	}
	var disallows, sitemaps []string
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		switch {
		case strings.HasPrefix(low, "disallow:"):
			if p := strings.TrimSpace(l[len("disallow:"):]); p != "" && p != "/" {
				disallows = append(disallows, p)
			}
		case strings.HasPrefix(low, "sitemap:"):
			sitemaps = append(sitemaps, strings.TrimSpace(l[len("sitemap:"):]))
		}
	}
	return map[string]any{
		"present":        true,
		"status_code":    status,
		"disallowed":     disallows,
		"disallow_count": len(disallows),
		"sitemaps":       sitemaps,
		"size_bytes":     len(body),
	}, nil
}

// --- security.txt ---

type securityTxtModule struct{}

func init() { engine.Register(securityTxtModule{}) }

func (securityTxtModule) Name() string { return "security_txt" }
func (securityTxtModule) Description() string {
	return "Checks for an RFC 9116 security.txt and reports contact/policy fields."
}
func (securityTxtModule) Category() string       { return "recon" }
func (securityTxtModule) Dependencies() []string { return nil }
func (securityTxtModule) RequiredKey() string    { return "" }
func (securityTxtModule) RateLimitRPM() int      { return 0 }

func (securityTxtModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	base := strings.TrimRight(target.URL, "/")
	for _, p := range []string{"/.well-known/security.txt", "/security.txt"} {
		body, status, _ := fetchText(ctx, client, base+p)
		if status == 200 && strings.Contains(strings.ToLower(body), "contact:") {
			fields := map[string][]string{}
			for _, line := range strings.Split(body, "\n") {
				if i := strings.Index(line, ":"); i > 0 {
					k := strings.ToLower(strings.TrimSpace(line[:i]))
					v := strings.TrimSpace(line[i+1:])
					if v != "" && !strings.HasPrefix(k, "#") {
						fields[k] = append(fields[k], v)
					}
				}
			}
			return map[string]any{"present": true, "path": p, "fields": fields}, nil
		}
	}
	return map[string]any{
		"present":          false,
		"findings":         []map[string]any{{"name": "No security.txt", "severity": "low", "description": "Publish an RFC 9116 security.txt with a Contact field."}},
		"overall_severity": "low",
	}, nil
}

// --- HTTP methods (OPTIONS) ---

type httpMethodsModule struct{}

func init() { engine.Register(httpMethodsModule{}) }

func (httpMethodsModule) Name() string { return "http_methods" }
func (httpMethodsModule) Description() string {
	return "Enumerates allowed HTTP methods (OPTIONS) and flags dangerous ones (PUT/DELETE/TRACE)."
}
func (httpMethodsModule) Category() string       { return "recon" }
func (httpMethodsModule) Dependencies() []string { return nil }
func (httpMethodsModule) RequiredKey() string    { return "" }
func (httpMethodsModule) RateLimitRPM() int      { return 0 }

func (httpMethodsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	resp, err := client.Do(ctx, http.MethodOptions, target.URL, nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	resp.Body.Close()
	allow := resp.Header.Get("Allow")
	methods := splitTrim(allow)

	findings := []map[string]any{}
	for _, m := range methods {
		switch strings.ToUpper(m) {
		case "PUT", "DELETE":
			findings = append(findings, map[string]any{"name": m + " method enabled", "severity": "medium", "description": "Write/delete HTTP method exposed."})
		case "TRACE", "TRACK":
			findings = append(findings, map[string]any{"name": m + " method enabled", "severity": "medium", "description": "TRACE/TRACK can enable Cross-Site Tracing."})
		}
	}
	overall := "info"
	if len(findings) > 0 {
		overall = "medium"
	}
	return map[string]any{
		"allow":            allow,
		"methods":          methods,
		"findings":         findings,
		"overall_severity": overall,
	}, nil
}

// --- CORS misconfiguration ---

type corsModule struct{}

func init() { engine.Register(corsModule{}) }

func (corsModule) Name() string { return "cors" }
func (corsModule) Description() string {
	return "Tests CORS policy with a crafted Origin — flags wildcard or reflected Origin with credentials."
}
func (corsModule) Category() string       { return "recon" }
func (corsModule) Dependencies() []string { return nil }
func (corsModule) RequiredKey() string    { return "" }
func (corsModule) RateLimitRPM() int      { return 0 }

func (corsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	evil := "https://evil.example.com"
	req, err := buildReq(ctx, http.MethodGet, target.URL, map[string]string{"Origin": evil})
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	resp, err := client.RawDo(req)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	resp.Body.Close()
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	findings := []map[string]any{}
	switch {
	case acao == "*":
		findings = append(findings, map[string]any{"name": "Wildcard CORS", "severity": "medium", "description": "Access-Control-Allow-Origin: * exposes responses to any origin."})
	case acao == evil:
		sev := "high"
		desc := "Origin is reflected in Access-Control-Allow-Origin."
		if strings.EqualFold(acac, "true") {
			sev = "critical"
			desc = "Reflected Origin WITH credentials — cross-origin data theft possible."
		}
		findings = append(findings, map[string]any{"name": "Reflected CORS Origin", "severity": sev, "description": desc})
	}
	overall := "info"
	if len(findings) > 0 {
		overall = findings[0]["severity"].(string)
	}
	return map[string]any{
		"allow_origin":      acao,
		"allow_credentials": acac,
		"reflects_origin":   acao == evil,
		"findings":          findings,
		"overall_severity":  overall,
	}, nil
}

// --- Cookie security audit ---

type cookieAuditModule struct{}

func init() { engine.Register(cookieAuditModule{}) }

func (cookieAuditModule) Name() string { return "cookie_audit" }
func (cookieAuditModule) Description() string {
	return "Audits Set-Cookie flags — flags cookies missing Secure, HttpOnly, or SameSite."
}
func (cookieAuditModule) Category() string       { return "recon" }
func (cookieAuditModule) Dependencies() []string { return nil }
func (cookieAuditModule) RequiredKey() string    { return "" }
func (cookieAuditModule) RateLimitRPM() int      { return 0 }

func (cookieAuditModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	resp, err := client.Get(ctx, target.URL)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	resp.Body.Close()
	cookies := resp.Cookies()
	rows := make([]map[string]any, 0, len(cookies))
	findings := []map[string]any{}
	for _, c := range cookies {
		sameSite := c.SameSite != http.SameSiteDefaultMode
		rows = append(rows, map[string]any{
			"name": c.Name, "secure": c.Secure, "http_only": c.HttpOnly, "samesite": sameSite,
		})
		var missing []string
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if !sameSite {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			findings = append(findings, map[string]any{
				"name":     "Cookie '" + c.Name + "' missing " + strings.Join(missing, ", "),
				"severity": "low", "description": "Harden cookie attributes to reduce theft/CSRF risk.",
			})
		}
	}
	overall := "info"
	if len(findings) > 0 {
		overall = "low"
	}
	return map[string]any{
		"cookie_count":     len(cookies),
		"cookies":          rows,
		"findings":         findings,
		"overall_severity": overall,
	}, nil
}

// ---- shared helpers ----

func fetchText(ctx context.Context, client *httpx.Client, url string) (string, int, error) {
	resp, err := client.Get(ctx, url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(body), resp.StatusCode, nil
}

func buildReq(ctx context.Context, method, url string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func splitTrim(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
