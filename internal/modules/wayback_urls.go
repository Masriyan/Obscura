package modules

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// waybackModule ports modules/wayback_urls.py (name "wayback_urls"): mines the
// Internet Archive CDX API for historical URLs and flags interesting ones.
type waybackModule struct{}

func init() { engine.Register(waybackModule{}) }

func (waybackModule) Name() string { return "wayback_urls" }
func (waybackModule) Description() string {
	return "Mines Wayback Machine for historical URLs — surfaces forgotten endpoints, leaked files, and historical attack surface."
}
func (waybackModule) Category() string       { return "recon" }
func (waybackModule) Dependencies() []string { return nil }
func (waybackModule) RequiredKey() string    { return "" }
func (waybackModule) RateLimitRPM() int      { return 20 }

var (
	criticalExts = set("sql", "bak", "backup", "env", "key", "pem", "p12", "pfx", "crt", "cer")
	highExts     = set("zip", "tar", "gz", "7z", "rar", "tgz", "conf", "config", "cfg", "ini", "xml", "yml", "yaml")
	mediumExts   = set("log", "csv", "xls", "xlsx", "doc", "docx", "pdf", "json", "txt", "db", "sqlite")

	sensitivePathRe = regexp.MustCompile(`(?i)(/admin|/login|/dashboard|/portal|/manage|/backup|/backups|/old|/dev|/test|/staging|/debug|/config|/setup|/install|/api/|/v[0-9]+/|\.git/|\.svn/|wp-admin|wp-content|phpmyadmin|\.env$|\.htaccess$|\.htpasswd$|web\.config$|/console|/actuator|/metrics|/health)`)
	criticalPathRe  = regexp.MustCompile(`(?i)(\.env$|\.git/|\.htpasswd$|web\.config$)`)
	highPathRe      = regexp.MustCompile(`(?i)(/backup|/backups|/old|/debug|/console|/actuator)`)
	extRe           = regexp.MustCompile(`(?i)\.([a-z0-9]{1,8})(?:[?#].*)?$`)
)

func (waybackModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	domain := target.Host
	res := map[string]any{
		"domain": domain, "total_urls": 0, "interesting_count": 0,
		"interesting_urls": []any{}, "file_types": map[string]int{}, "top_paths": map[string]int{},
		"years_active": []string{}, "severity": "info",
	}

	cdx := "https://web.archive.org/cdx/search/cdx?url=*." + domain + "/*&output=json&fl=original,statuscode,timestamp&collapse=urlkey&limit=3000&filter=statuscode:200"
	resp, err := client.Get(ctx, cdx)
	if err != nil {
		res["error"] = err.Error()
		return res, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) < 2 {
		res["message"] = "No historical URLs indexed for this domain."
		return res, nil
	}

	seen := map[string]bool{}
	years := map[string]bool{}
	fileTypes := map[string]int{}
	pathCounts := map[string]int{}
	var interesting []map[string]any

	for _, row := range rows[1:] { // skip header
		if len(row) < 3 {
			continue
		}
		rawURL, ts := row[0], row[2]
		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true
		if len(ts) >= 4 {
			years[ts[:4]] = true
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		path := strings.ToLower(u.Path)
		ext := ""
		if m := extRe.FindStringSubmatch(path); m != nil {
			ext = strings.ToLower(m[1])
			fileTypes[ext]++
		}
		if parts := strings.Split(path, "/"); len(parts) > 1 && parts[1] != "" {
			pathCounts["/"+parts[1]]++
		}
		if sev := classifyWayback(path, ext); sev != "none" {
			year := "?"
			if len(ts) >= 4 {
				year = ts[:4]
			}
			interesting = append(interesting, map[string]any{
				"url": rawURL, "year": year, "severity": sev, "reasons": waybackReasons(path, ext),
			})
		}
	}

	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2}
	sort.SliceStable(interesting, func(i, j int) bool {
		return sevOrder[interesting[i]["severity"].(string)] < sevOrder[interesting[j]["severity"].(string)]
	})

	overall := "info"
	high := 0
	for _, it := range interesting {
		s := it["severity"].(string)
		if s == "critical" {
			overall = "critical"
		} else if s == "high" && overall != "critical" {
			overall = "high"
		} else if overall == "info" {
			overall = "medium"
		}
		if s == "critical" || s == "high" {
			high++
		}
	}

	res["total_urls"] = len(seen)
	res["interesting_count"] = len(interesting)
	res["interesting_urls"] = capAny(interesting, 60)
	res["file_types"] = topN(fileTypes, 20)
	res["top_paths"] = topN(pathCounts, 20)
	res["years_active"] = sortedKeys(years)
	res["high_value_count"] = high
	res["severity"] = overall
	return res, nil
}

func classifyWayback(path, ext string) string {
	if criticalExts[ext] {
		return "critical"
	}
	if sensitivePathRe.MatchString(path) {
		if criticalPathRe.MatchString(path) {
			return "critical"
		}
		if highPathRe.MatchString(path) {
			return "high"
		}
		return "medium"
	}
	if highExts[ext] {
		return "high"
	}
	if mediumExts[ext] {
		return "medium"
	}
	return "none"
}

func waybackReasons(path, ext string) []string {
	var r []string
	if criticalExts[ext] || highExts[ext] || mediumExts[ext] {
		r = append(r, "file type: ."+ext)
	}
	if m := sensitivePathRe.FindString(path); m != "" {
		r = append(r, "sensitive path: "+strings.Trim(m, "/"))
	}
	if len(r) == 0 {
		return []string{"historical URL"}
	}
	if len(r) > 2 {
		r = r[:2]
	}
	return r
}

// ---- small generic helpers ----

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capAny(s []map[string]any, n int) []map[string]any {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func topN(m map[string]int, n int) map[string]int {
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	out := map[string]int{}
	for i, e := range arr {
		if i >= n {
			break
		}
		out[e.k] = e.v
	}
	return out
}
