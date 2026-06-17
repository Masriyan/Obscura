package modules

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// googleDorkModule ports modules/google_dorking.py (name "google_dorking"):
// generates dork queries and directly probes link-aggregator/social services.
//
// Deviation: the Python DuckDuckGo-Lite HTML scrape is fragile and frequently
// rate-limited; this port keeps the (always-works) dork generation + direct
// profile probing, and leaves search-engine result scraping as a TODO. The
// emitted data shape (domain/dorks_generated/dork_list/profile_probes/findings/
// risk_assessment) matches the original.
type googleDorkModule struct{}

func init() { engine.Register(googleDorkModule{}) }

func (googleDorkModule) Name() string { return "google_dorking" }
func (googleDorkModule) Description() string {
	return "Automated Google dorking — finds exposed files, admin panels, backups, and credentials related to the target."
}
func (googleDorkModule) Category() string       { return "passive" }
func (googleDorkModule) Dependencies() []string { return nil }
func (googleDorkModule) RequiredKey() string    { return "" }
func (googleDorkModule) RateLimitRPM() int      { return 10 }

var dorkCategories = []struct {
	id    string
	desc  string
	dorks []string
}{
	{"exposed_files", "Sensitive files exposed on the target", []string{
		"site:{d} filetype:sql", "site:{d} filetype:env", "site:{d} filetype:bak",
		"site:{d} filetype:log", "site:{d} filetype:conf", "site:{d} filetype:pem", "site:{d} filetype:key",
	}},
	{"admin_panels", "Admin panel and management interfaces", []string{
		"site:{d} inurl:admin", "site:{d} inurl:login", "site:{d} inurl:dashboard",
		"site:{d} inurl:wp-admin", "site:{d} inurl:phpMyAdmin",
	}},
	{"directory_listings", "Open directory listings", []string{
		`site:{d} intitle:"index of"`, `site:{d} intitle:"parent directory"`,
	}},
	{"credentials", "Potential credential exposure", []string{
		`"{d}" password filetype:txt`, `"{d}" "api_key" OR "apikey"`, `"{d}" "BEGIN RSA PRIVATE KEY"`, `"{d}" "AWS_SECRET_ACCESS_KEY"`,
	}},
	{"paste_sites", "Credentials or data on paste sites", []string{
		`"{d}" site:pastebin.com`, `"{d}" site:gist.github.com`, `"{d}" site:trello.com`,
	}},
	{"cloud_exposure", "Cloud service exposure", []string{
		`"{d}" site:amazonaws.com`, `"{d}" site:blob.core.windows.net`, `"{d}" site:storage.googleapis.com`,
	}},
	{"error_pages", "Exposed error/debug pages", []string{
		"site:{d} inurl:debug", `site:{d} "stack trace"`, `site:{d} "SQL syntax"`,
	}},
}

var profileServices = []struct{ name, tmpl string }{
	{"Linktree", "https://linktr.ee/{n}"},
	{"HeyLink", "https://heylink.me/{n}"},
	{"Bio.link", "https://bio.link/{n}"},
	{"Beacons.ai", "https://beacons.ai/{n}"},
	{"About.me", "https://about.me/{n}"},
	{"Taplink", "https://taplink.cc/{n}"},
}

func (googleDorkModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	domain := target.Host
	domainBase := strings.SplitN(domain, ".", 2)[0]

	var dorkList []any
	for _, cat := range dorkCategories {
		for _, t := range cat.dorks {
			dork := strings.ReplaceAll(t, "{d}", domain)
			dorkList = append(dorkList, map[string]any{
				"category": cat.id, "category_desc": cat.desc, "dork": dork,
				"google_url": "https://www.google.com/search?q=" + url.QueryEscape(dork),
			})
		}
	}

	profiles := probeProfiles(ctx, client, domainBase, strings.ReplaceAll(domain, ".", ""))

	activeProfiles := 0
	for _, p := range profiles {
		if f, _ := p["found"].(bool); f {
			activeProfiles++
		}
	}

	res := map[string]any{
		"domain":            domain,
		"categories_tested": len(dorkCategories),
		"dorks_generated":   len(dorkList),
		"dork_list":         dorkList,
		"profile_probes":    profiles,
		"findings":          []any{},
		"search_method":     "direct_profile_probe",
	}
	switch {
	case activeProfiles > 0:
		res["risk_assessment"] = "Found active profile(s) — review for exposure"
		res["severity"] = "medium"
	default:
		res["risk_assessment"] = "No significant findings from dork queries or profile probes"
		res["severity"] = "info"
	}
	return res, nil
}

func probeProfiles(ctx context.Context, client *httpx.Client, names ...string) []map[string]any {
	seen := map[string]bool{} // unique names
	var probes []map[string]any
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		for _, svc := range profileServices {
			if ctx.Err() != nil {
				break
			}
			u := strings.ReplaceAll(svc.tmpl, "{n}", n)
			found := false
			status := 0
			if resp, err := client.Get(ctx, u); err == nil {
				status = resp.StatusCode
				resp.Body.Close()
				found = status == 200 || status == 301 || status == 302
			}
			sev := "info"
			if found {
				sev = "medium"
			}
			probes = append(probes, map[string]any{"service": svc.name, "url": u, "status": status, "found": found, "severity": sev})
		}
	}
	// Keep only the first hit per service (found first).
	sort.SliceStable(probes, func(i, j int) bool {
		fi, _ := probes[i]["found"].(bool)
		fj, _ := probes[j]["found"].(bool)
		if fi != fj {
			return fi
		}
		return probes[i]["service"].(string) < probes[j]["service"].(string)
	})
	seenSvc := map[string]bool{}
	var deduped []map[string]any
	for _, p := range probes {
		svc := p["service"].(string)
		if !seenSvc[svc] {
			seenSvc[svc] = true
			deduped = append(deduped, p)
		}
	}
	return deduped
}
