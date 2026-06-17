package modules

import (
	"context"
	"io"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// collectScripts fetches the target page and up to maxJS linked scripts,
// returning the page HTML plus a map of script-URL -> content. Shared by the
// JS-analysis modules (js_endpoints, source_maps).
func collectScripts(ctx context.Context, client *httpx.Client, target safety.Target, maxJS int) (string, map[string]string) {
	scripts := map[string]string{}
	base, err := url.Parse(target.URL)
	if err != nil {
		return "", scripts
	}
	resp, err := client.Get(ctx, target.URL)
	if err != nil {
		return "", scripts
	}
	htmlBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 3<<20))
	resp.Body.Close()
	html := string(htmlBytes)

	doc, derr := goquery.NewDocumentFromReader(strings.NewReader(html))
	if derr != nil {
		return html, scripts
	}
	var urls []string
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			if u, err := url.Parse(strings.TrimSpace(src)); err == nil {
				urls = append(urls, base.ResolveReference(u).String())
			}
		}
	})
	for i, ju := range urls {
		if i >= maxJS || ctx.Err() != nil {
			break
		}
		if r, err := client.Get(ctx, ju); err == nil {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			r.Body.Close()
			scripts[ju] = string(b)
		}
	}
	return html, scripts
}
