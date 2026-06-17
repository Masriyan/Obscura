package modules

import (
	"context"
	"io"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// httpProbeModule ports modules/http_probe.py (name "http_probe"): smart probing
// for exposed files/misconfigurations with content-based validation.
type httpProbeModule struct{}

func init() { engine.Register(httpProbeModule{}) }

func (httpProbeModule) Name() string { return "http_probe" }
func (httpProbeModule) Description() string {
	return "Enhanced HTTP security probing — detects exposed Git repos, .env files, debug endpoints with content validation."
}
func (httpProbeModule) Category() string       { return "semi-offensive" }
func (httpProbeModule) Dependencies() []string { return nil }
func (httpProbeModule) RequiredKey() string    { return "" }
func (httpProbeModule) RateLimitRPM() int      { return 60 }

type probe struct {
	path        string
	name        string
	severity    string
	description string
	validate    func(string) bool
}

func containsAny(text string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

var probes = []probe{
	{"/.git/HEAD", "Git Repository", "critical", "Git repository is publicly accessible — full source code download possible", func(t string) bool { return strings.HasPrefix(t, "ref: refs/") }},
	{"/.git/config", "Git Config", "critical", "Git configuration exposed — may reveal remote repository URLs", func(t string) bool { return containsAny(t, "[core]", "[remote") }},
	{"/.env", "Environment File", "critical", "Environment file with credentials is publicly accessible", func(t string) bool {
		return containsAny(t, "DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL")
	}},
	{"/.env.production", "Production Env", "critical", "Production environment file exposed", func(t string) bool { return strings.Contains(t, "=") && len(t) > 10 }},
	{"/server-status", "Apache Status", "high", "Apache mod_status is publicly accessible — reveals server internals", func(t string) bool { return containsAny(t, "Apache Server Status", "Server Version") }},
	{"/phpinfo.php", "PHP Info", "high", "phpinfo() page exposes detailed server configuration", func(t string) bool { return containsAny(t, "PHP Version", "phpinfo()") }},
	{"/actuator", "Spring Actuator", "high", "Spring Boot Actuator endpoints are publicly accessible", func(t string) bool { return strings.Contains(t, `"_links"`) && strings.Contains(t, "actuator") }},
	{"/actuator/env", "Spring Actuator Env", "critical", "Spring Boot environment variables exposed", func(t string) bool { return strings.Contains(t, `"propertySources"`) }},
	{"/web.config", ".NET Web Config", "critical", ".NET web.config exposed — may contain connection strings", func(t string) bool { return strings.Contains(strings.ToLower(t), "<configuration>") }},
	{"/backup.sql", "SQL Backup", "critical", "SQL database backup is publicly downloadable", func(t string) bool { return containsAny(t, "CREATE TABLE", "INSERT INTO") }},
	{"/swagger.json", "Swagger API Spec", "medium", "API documentation (Swagger/OpenAPI) is publicly accessible", func(t string) bool { return containsAny(t, `"swagger"`, `"openapi"`) }},
	{"/package.json", "Node.js Package", "medium", "package.json exposed — reveals tech stack and dependencies", func(t string) bool { return containsAny(t, `"dependencies"`, `"scripts"`) }},
	{"/composer.json", "Composer Package", "medium", "composer.json exposed — reveals PHP dependencies", func(t string) bool { return strings.Contains(t, `"require"`) && strings.Contains(t, `"name"`) }},
}

func (httpProbeModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	base := strings.TrimRight(target.URL, "/")
	findings := []map[string]any{}
	summary := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		if f := runProbe(ctx, client, base, p); f != nil {
			findings = append(findings, f)
			if _, ok := summary[p.severity]; ok {
				summary[p.severity]++
			}
		}
	}

	res := map[string]any{
		"target":     target.URL,
		"probes_run": len(probes),
		"findings":   findings,
		"summary":    summary,
	}

	switch {
	case summary["critical"] > 0:
		res["risk_assessment"] = "CRITICAL: critical exposure(s) found. Immediate remediation required."
		res["overall_severity"] = "critical"
	case summary["high"] > 0:
		res["risk_assessment"] = "HIGH: high-severity exposure(s) found."
		res["overall_severity"] = "high"
	case len(findings) > 0:
		res["risk_assessment"] = "Exposure(s) found — review recommended."
		res["overall_severity"] = "medium"
	default:
		res["risk_assessment"] = "No sensitive files or misconfigurations detected."
		res["overall_severity"] = "info"
	}
	return res, nil
}

func runProbe(ctx context.Context, client *httpx.Client, base string, p probe) map[string]any {
	resp, err := client.Get(ctx, base+p.path)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1MiB
	if err != nil {
		return nil
	}
	text := string(body)
	if !p.validate(text) {
		return nil
	}
	preview := text
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return map[string]any{
		"vulnerable":      true,
		"path":            p.path,
		"name":            p.name,
		"severity":        p.severity,
		"description":     p.description,
		"url":             base + p.path,
		"status_code":     resp.StatusCode,
		"content_length":  len(text),
		"content_preview": preview,
	}
}
