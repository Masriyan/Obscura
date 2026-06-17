package modules

import (
	"context"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// jsSecretsModule scans the page and its linked JavaScript for leaked secrets
// (name "js_secrets") using known token patterns.
type jsSecretsModule struct{}

func init() { engine.Register(jsSecretsModule{}) }

func (jsSecretsModule) Name() string { return "js_secrets" }
func (jsSecretsModule) Description() string {
	return "Scans inline and linked JavaScript for leaked API keys, tokens, and private keys."
}
func (jsSecretsModule) Category() string       { return "recon" }
func (jsSecretsModule) Dependencies() []string { return nil }
func (jsSecretsModule) RequiredKey() string    { return "" }
func (jsSecretsModule) RateLimitRPM() int      { return 60 }

var secretPatterns = []struct {
	name, severity string
	re             *regexp.Regexp
}{
	{"AWS Access Key", "critical", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API Key", "high", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"GitHub Token", "critical", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"Slack Token", "high", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"Slack Webhook", "high", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}`)},
	{"Stripe Live Key", "critical", regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`)},
	{"Twilio Key", "high", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	{"Mailgun Key", "high", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{"JWT", "medium", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Private Key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"Google OAuth", "high", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
}

func (jsSecretsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	base, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(ctx, target.URL)
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	htmlBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	html := string(htmlBytes)

	sources := map[string]string{target.URL: html} // url -> content
	if doc, derr := goquery.NewDocumentFromReader(strings.NewReader(html)); derr == nil {
		var jsURLs []string
		doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
			if src, ok := s.Attr("src"); ok {
				if u, err := url.Parse(strings.TrimSpace(src)); err == nil {
					jsURLs = append(jsURLs, base.ResolveReference(u).String())
				}
			}
		})
		for i, ju := range jsURLs {
			if i >= 15 || ctx.Err() != nil {
				break
			}
			if r, err := client.Get(ctx, ju); err == nil {
				b, _ := io.ReadAll(io.LimitReader(r.Body, 3<<20))
				r.Body.Close()
				sources[ju] = string(b)
			}
		}
	}

	seen := map[string]bool{}
	findings := []map[string]any{}
	for src, content := range sources {
		for _, p := range secretPatterns {
			for _, m := range p.re.FindAllString(content, -1) {
				key := p.name + "|" + m
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, map[string]any{
					"name": p.name + " leaked", "severity": p.severity,
					"description": "Pattern match in " + shortURL(src),
					"match":       redactSecret(m), "source": src,
				})
			}
		}
	}

	overall := "info"
	for _, f := range findings {
		switch f["severity"] {
		case "critical":
			overall = "critical"
		case "high":
			if overall != "critical" {
				overall = "high"
			}
		case "medium":
			if overall == "info" {
				overall = "medium"
			}
		}
	}
	return map[string]any{
		"sources_scanned":  len(sources),
		"findings":         findings,
		"secrets_found":    len(findings),
		"overall_severity": overall,
	}, nil
}

// redactSecret keeps the first/last few chars and masks the middle.
func redactSecret(s string) string {
	if len(s) <= 10 {
		return s[:2] + strings.Repeat("•", len(s)-2)
	}
	return s[:6] + strings.Repeat("•", 6) + s[len(s)-4:]
}

func shortURL(u string) string {
	if len(u) > 70 {
		return u[:67] + "…"
	}
	return u
}
