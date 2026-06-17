package modules

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// jsEndpointsModule extracts endpoints, URLs, and parameters from linked JS
// (name "js_endpoints") — a LinkFinder-style attack-surface multiplier.
type jsEndpointsModule struct{}

func init() { engine.Register(jsEndpointsModule{}) }

func (jsEndpointsModule) Name() string { return "js_endpoints" }
func (jsEndpointsModule) Description() string {
	return "Extracts hidden API paths, URLs, and parameters from linked JavaScript (LinkFinder-style)."
}
func (jsEndpointsModule) Category() string       { return "recon" }
func (jsEndpointsModule) Dependencies() []string { return nil }
func (jsEndpointsModule) RequiredKey() string    { return "" }
func (jsEndpointsModule) RateLimitRPM() int      { return 60 }

var (
	reFullURL = regexp.MustCompile(`https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
	// Quoted relative/absolute paths, e.g. "/api/v1/users", '/graphql?x=1'.
	rePath  = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_\-/.]{2,}(?:\?[a-zA-Z0-9_\-=&%.]*)?)["'` + "`" + `]`)
	reNoise = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|webm)(\?|$)`)
)

func (jsEndpointsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	page, scripts := collectScripts(ctx, client, target, 20)
	corpus := page
	for _, c := range scripts {
		corpus += "\n" + c
	}
	host := target.Host

	urls := map[string]bool{}
	paths := map[string]bool{}
	apiPaths := map[string]bool{}
	params := map[string]bool{}

	for _, u := range reFullURL.FindAllString(corpus, -1) {
		u = strings.TrimRight(u, `"'`+"`"+`),;`)
		if reNoise.MatchString(u) {
			continue
		}
		urls[u] = true
		collectParams(u, params)
	}
	for _, m := range rePath.FindAllStringSubmatch(corpus, -1) {
		p := m[1]
		if reNoise.MatchString(p) || p == "//" {
			continue
		}
		paths[p] = true
		if isAPIPath(p) {
			apiPaths[p] = true
		}
		collectParams(p, params)
	}

	// Same-host URLs are the most actionable.
	var sameHost []string
	for u := range urls {
		if pu, err := url.Parse(u); err == nil && strings.Contains(pu.Host, host) {
			sameHost = append(sameHost, u)
		}
	}

	return map[string]any{
		"scripts_analyzed":   len(scripts),
		"full_urls":          capSorted(urls, 200),
		"same_host_urls":     capList(sameHost, 200),
		"paths":              capSorted(paths, 300),
		"api_endpoints":      capSorted(apiPaths, 200),
		"parameters":         capSorted(params, 200),
		"total_endpoints":    len(paths) + len(urls),
		"api_endpoint_count": len(apiPaths),
	}, nil
}

func isAPIPath(p string) bool {
	low := strings.ToLower(p)
	for _, k := range []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc", "/oauth", "/auth/", "/.json", "/admin", "/internal"} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return strings.HasSuffix(low, ".json")
}

func collectParams(rawurl string, into map[string]bool) {
	i := strings.IndexByte(rawurl, '?')
	if i < 0 {
		return
	}
	for _, pair := range strings.Split(rawurl[i+1:], "&") {
		if eq := strings.IndexByte(pair, '='); eq > 0 {
			name := pair[:eq]
			if name != "" && len(name) < 40 {
				into[name] = true
			}
		}
	}
}

func capSorted(m map[string]bool, n int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return capList(out, n)
}

func capList(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
