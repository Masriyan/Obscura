package modules

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// sourceMapsModule finds JavaScript source maps (name "source_maps"), which
// often expose the entire original, unminified source tree.
type sourceMapsModule struct{}

func init() { engine.Register(sourceMapsModule{}) }

func (sourceMapsModule) Name() string { return "source_maps" }
func (sourceMapsModule) Description() string {
	return "Detects exposed JavaScript source maps (.js.map) that leak original source code and file paths."
}
func (sourceMapsModule) Category() string       { return "recon" }
func (sourceMapsModule) Dependencies() []string { return nil }
func (sourceMapsModule) RequiredKey() string    { return "" }
func (sourceMapsModule) RateLimitRPM() int      { return 60 }

var reSourceMappingURL = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)

func (sourceMapsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	_, scripts := collectScripts(ctx, client, target, 25)

	found := []map[string]any{}
	findings := []map[string]any{}
	checked := map[string]bool{}

	tryMap := func(jsURL, mapURL string) {
		if mapURL == "" || checked[mapURL] {
			return
		}
		checked[mapURL] = true
		body := fetchBody(ctx, client, mapURL)
		if body == "" {
			return
		}
		var sm struct {
			Version int      `json:"version"`
			Sources []string `json:"sources"`
		}
		if err := json.Unmarshal([]byte(body), &sm); err != nil || sm.Version == 0 {
			return
		}
		sample := sm.Sources
		if len(sample) > 15 {
			sample = sample[:15]
		}
		found = append(found, map[string]any{
			"js": jsURL, "map_url": mapURL, "sources_count": len(sm.Sources), "sample_sources": sample,
		})
		findings = append(findings, map[string]any{
			"name": "Exposed source map", "severity": "medium",
			"description": "Source map reveals original source for " + shortURL(jsURL) + " (" + itoa(len(sm.Sources)) + " files).",
			"url":         mapURL,
		})
	}

	for jsURL, content := range scripts {
		if ctx.Err() != nil {
			break
		}
		// 1) Explicit sourceMappingURL comment.
		if m := reSourceMappingURL.FindStringSubmatch(content); m != nil {
			ref := strings.TrimSpace(m[1])
			if !strings.HasPrefix(ref, "data:") {
				tryMap(jsURL, resolveAgainst(jsURL, ref))
			}
		}
		// 2) Convention: <script>.map next to the JS.
		if u, err := url.Parse(jsURL); err == nil && strings.HasSuffix(u.Path, ".js") {
			tryMap(jsURL, jsURL+".map")
		}
	}

	overall := "info"
	if len(found) > 0 {
		overall = "medium"
	}
	return map[string]any{
		"scripts_analyzed": len(scripts),
		"source_maps":      found,
		"maps_found":       len(found),
		"findings":         findings,
		"overall_severity": overall,
	}, nil
}

func resolveAgainst(baseURL, ref string) string {
	b, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}
