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

// subdomainTakeoverModule detects dangling-CNAME subdomain takeovers (name
// "subdomain_takeover"): a subdomain whose CNAME points to a deprovisioned
// third-party service that still serves a claimable "not found" page.
type subdomainTakeoverModule struct{}

func init() { engine.Register(subdomainTakeoverModule{}) }

func (subdomainTakeoverModule) Name() string { return "subdomain_takeover" }
func (subdomainTakeoverModule) Description() string {
	return "Detects subdomain takeover via dangling CNAMEs pointing to claimable third-party services."
}
func (subdomainTakeoverModule) Category() string       { return "semi-offensive" }
func (subdomainTakeoverModule) Dependencies() []string { return []string{"subdomain_scan"} }
func (subdomainTakeoverModule) RequiredKey() string    { return "" }
func (subdomainTakeoverModule) RateLimitRPM() int      { return 60 }

// takeoverSig maps a CNAME substring to the service + its takeover fingerprint.
var takeoverSigs = []struct{ cname, service, fingerprint, severity string }{
	{"github.io", "GitHub Pages", "There isn't a GitHub Pages site here", "high"},
	{"herokuapp.com", "Heroku", "No such app", "high"},
	{"herokudns.com", "Heroku", "No such app", "high"},
	{"s3.amazonaws.com", "AWS S3", "NoSuchBucket", "critical"},
	{"s3-website", "AWS S3", "The specified bucket does not exist", "critical"},
	{"myshopify.com", "Shopify", "Sorry, this shop is currently unavailable", "high"},
	{"fastly.net", "Fastly", "Fastly error: unknown domain", "high"},
	{"surge.sh", "Surge.sh", "project not found", "medium"},
	{"bitbucket.io", "Bitbucket", "Repository not found", "medium"},
	{"ghost.io", "Ghost", "The thing you were looking for is no longer here", "medium"},
	{"wordpress.com", "WordPress", "Do you want to register", "medium"},
	{"pantheonsite.io", "Pantheon", "The gods are wise, but do not know of the site", "high"},
	{"zendesk.com", "Zendesk", "Help Center Closed", "medium"},
	{"readme.io", "Readme.io", "Project doesnt exist", "medium"},
	{"cloudapp.net", "Azure", "404 Web Site not found", "high"},
	{"azurewebsites.net", "Azure", "404 Web Site not found", "high"},
}

func (subdomainTakeoverModule) Run(ctx context.Context, target safety.Target, deps *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	// Gather candidate hosts: discovered subdomains plus the apex.
	hosts := map[string]bool{target.Host: true}
	if data, ok := deps.Get("subdomain_scan"); ok {
		if found, ok := data["found"].([]any); ok {
			for _, f := range found {
				if m, ok := f.(map[string]any); ok {
					if s, _ := m["subdomain"].(string); s != "" {
						hosts[strings.ToLower(s)] = true
					}
				}
			}
		}
	}

	checked := 0
	findings := []map[string]any{}
	for host := range hosts {
		if ctx.Err() != nil || checked >= 60 {
			break
		}
		cname := lookupCNAME(ctx, host)
		if cname == "" {
			continue
		}
		checked++
		for _, sig := range takeoverSigs {
			if !strings.Contains(cname, sig.cname) {
				continue
			}
			// CNAME points at the service — confirm the claimable fingerprint.
			body := fetchBody(ctx, client, "https://"+host)
			if body == "" {
				body = fetchBody(ctx, client, "http://"+host)
			}
			if strings.Contains(body, sig.fingerprint) {
				findings = append(findings, map[string]any{
					"name": "Subdomain takeover: " + host, "severity": sig.severity,
					"description": "CNAME points to unclaimed " + sig.service + " (" + cname + ").",
					"subdomain":   host, "cname": cname, "service": sig.service,
				})
			}
			break
		}
	}

	overall := "info"
	if len(findings) > 0 {
		overall = "high"
	}
	return map[string]any{
		"checked":          checked,
		"candidates":       len(hosts),
		"findings":         findings,
		"vulnerable":       len(findings) > 0,
		"overall_severity": overall,
	}, nil
}

func fetchBody(ctx context.Context, client *httpx.Client, url string) string {
	resp, err := client.Get(ctx, url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return string(b)
}
