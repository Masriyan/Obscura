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

// techModule fingerprints web technologies from response headers and HTML
// markers (name "tech"). Keyless, header/body-based detection.
type techModule struct{}

func init() { engine.Register(techModule{}) }

func (techModule) Name() string { return "tech" }
func (techModule) Description() string {
	return "Technology fingerprinting from headers and HTML (server, framework, CMS, analytics)."
}
func (techModule) Category() string       { return "recon" }
func (techModule) Dependencies() []string { return nil }
func (techModule) RequiredKey() string    { return "" }
func (techModule) RateLimitRPM() int      { return 0 }

var techHeaderSigs = []struct{ header, contains, tech string }{
	{"Server", "nginx", "Nginx"},
	{"Server", "apache", "Apache"},
	{"Server", "cloudflare", "Cloudflare"},
	{"Server", "microsoft-iis", "IIS"},
	{"Server", "litespeed", "LiteSpeed"},
	{"X-Powered-By", "php", "PHP"},
	{"X-Powered-By", "asp.net", "ASP.NET"},
	{"X-Powered-By", "express", "Express"},
	{"X-Aspnet-Version", "", "ASP.NET"},
	{"X-Generator", "drupal", "Drupal"},
	{"X-Drupal-Cache", "", "Drupal"},
	{"X-Shopify-Stage", "", "Shopify"},
}

var techBodySigs = []struct{ marker, tech string }{
	{"wp-content", "WordPress"},
	{"wp-includes", "WordPress"},
	{"/sites/all/", "Drupal"},
	{"Joomla!", "Joomla"},
	{"__NEXT_DATA__", "Next.js"},
	{"data-reactroot", "React"},
	{"ng-version", "Angular"},
	{"window.__NUXT__", "Nuxt.js"},
	{"csrf-param", "Ruby on Rails"},
	{"google-analytics.com", "Google Analytics"},
	{"gtag(", "Google Tag Manager"},
	{"Shopify.theme", "Shopify"},
}

func (techModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	resp, err := client.Get(ctx, target.URL)
	if err != nil {
		return map[string]any{"error": err.Error(), "target": target.URL}, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	html := string(body)

	set := map[string]bool{}
	for _, s := range techHeaderSigs {
		val := strings.ToLower(resp.Header.Get(s.header))
		if val == "" {
			continue
		}
		if s.contains == "" || strings.Contains(val, s.contains) {
			set[s.tech] = true
		}
	}
	for _, s := range techBodySigs {
		if strings.Contains(html, s.marker) {
			set[s.tech] = true
		}
	}

	return map[string]any{
		"target":       target.URL,
		"technologies": keysOf(set),
		"count":        len(set),
		"server":       resp.Header.Get("Server"),
		"powered_by":   resp.Header.Get("X-Powered-By"),
	}, nil
}
