package modules

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// crawlerModule ports modules/crawler.py (name "crawler"): a bounded same-host
// crawl extracting links, forms, scripts, emails, API endpoints, and comments.
type crawlerModule struct{}

func init() { engine.Register(crawlerModule{}) }

func (crawlerModule) Name() string { return "crawler" }
func (crawlerModule) Description() string {
	return "Same-host web crawler — maps internal links, forms, scripts, emails, API endpoints, and supply-chain risks."
}
func (crawlerModule) Category() string       { return "recon" }
func (crawlerModule) Dependencies() []string { return nil }
func (crawlerModule) RequiredKey() string    { return "" }
func (crawlerModule) RateLimitRPM() int      { return 60 }

const crawlMaxPages = 12

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (crawlerModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	base, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	host := base.Hostname()

	internalMap := []any{}
	externalSet := map[string]bool{}
	scriptSet := map[string]bool{}
	forms := []any{}
	emailSet := map[string]bool{}
	apiSet := map[string]bool{}
	comments := []string{}
	thirdParty := map[string]bool{}

	queue := []string{strings.TrimRight(target.URL, "/")}
	visited := map[string]bool{}
	stats := map[string]int{"pages_scanned": 0, "internal_count": 0, "external_count": 0, "broken_links": 0, "errors": 0}

	for len(queue) > 0 && stats["pages_scanned"] < crawlMaxPages {
		if ctx.Err() != nil {
			break
		}
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true

		resp, err := client.Get(ctx, cur)
		if err != nil {
			stats["errors"]++
			continue
		}
		status := resp.StatusCode
		if status >= 400 {
			stats["broken_links"]++
		}
		doc, derr := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		if derr != nil {
			stats["errors"]++
			continue
		}
		stats["pages_scanned"]++
		stats["internal_count"]++

		title := strings.TrimSpace(doc.Find("title").First().Text())
		if title == "" {
			title = "No Title"
		}
		internalMap = append(internalMap, map[string]any{"url": cur, "status": status, "title": title})

		// Emails from page text.
		for _, e := range emailRe.FindAllString(doc.Text(), -1) {
			emailSet[strings.ToLower(e)] = true
		}

		// Links.
		doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
			href, _ := s.Attr("href")
			abs := resolveRef(base, href)
			if abs == "" {
				return
			}
			u, err := url.Parse(abs)
			if err != nil {
				return
			}
			if u.Hostname() == host {
				if !visited[abs] && len(queue)+len(visited) < 200 {
					queue = append(queue, strings.TrimRight(abs, "/"))
				}
				if strings.Contains(u.Path, "/api/") || strings.HasSuffix(u.Path, ".json") {
					apiSet[u.Path] = true
				}
			} else if u.Scheme == "http" || u.Scheme == "https" {
				externalSet[abs] = true
			}
		})

		// Scripts (and third-party/supply-chain detection).
		doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
			src, _ := s.Attr("src")
			abs := resolveRef(base, src)
			if abs == "" {
				return
			}
			scriptSet[abs] = true
			if u, err := url.Parse(abs); err == nil && u.Hostname() != "" && u.Hostname() != host {
				thirdParty[u.Hostname()] = true
			}
		})

		// Forms.
		doc.Find("form").Each(func(_ int, s *goquery.Selection) {
			action, _ := s.Attr("action")
			method, _ := s.Attr("method")
			if method == "" {
				method = "GET"
			}
			var inputs []string
			s.Find("input[name]").Each(func(_ int, in *goquery.Selection) {
				if n, ok := in.Attr("name"); ok {
					inputs = append(inputs, n)
				}
			})
			forms = append(forms, map[string]any{
				"action": resolveRef(base, action), "method": strings.ToUpper(method),
				"inputs": inputs, "found_on": cur,
			})
		})

		// HTML comments.
		doc.Find("*").Contents().Each(func(_ int, s *goquery.Selection) {
			if len(s.Nodes) > 0 && s.Nodes[0].Type == 8 { // CommentNode
				c := strings.TrimSpace(s.Nodes[0].Data)
				if c != "" && len(comments) < 20 {
					comments = append(comments, truncate(c, 160))
				}
			}
		})
	}

	stats["external_count"] = len(externalSet)
	supplyRisks := []string{}
	if len(thirdParty) > 0 {
		supplyRisks = append(supplyRisks, "Page loads scripts from third-party hosts — supply-chain exposure.")
	}

	return map[string]any{
		"internal_map":               internalMap,
		"external_links":             keysOf(externalSet),
		"scripts":                    keysOf(scriptSet),
		"forms":                      forms,
		"emails":                     keysOf(emailSet),
		"api_endpoints":              keysOf(apiSet),
		"comments":                   comments,
		"sensitive_paths_discovered": []any{},
		"supply_chain":               map[string]any{"third_party_scripts": keysOf(thirdParty), "potential_risks": supplyRisks},
		"stats":                      stats,
	}, nil
}

func resolveRef(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "javascript:") ||
		strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "tel:") || strings.HasPrefix(ref, "data:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
