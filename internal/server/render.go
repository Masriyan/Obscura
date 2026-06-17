package server

import (
	"fmt"
	"html"
	"html/template"
	"sort"
	"strings"
)

// funcMap exposes rendering helpers to templates: a recursive "humanize" that
// turns arbitrary module data (map[string]any from JSON) into readable HTML,
// plus small formatting helpers.
func funcMap() template.FuncMap {
	return template.FuncMap{
		"humanize": func(v any) template.HTML { return template.HTML(humanizeValue(v, 0)) },
		"prettify": prettifyKey,
		"sevBadge": func(s string) template.HTML { return template.HTML(severityBadge(s)) },
		"gauge":    gaugeVar,
		"title":    prettifyKey,
		"lower":    strings.ToLower,
		"icon":     func(name string) template.HTML { return template.HTML(icon(name)) },
		"sub":      func(a, b int) int { return a - b },
		"mulpct": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a * 100 / b
		},
	}
}

// icon returns a 1.5px-stroke line SVG (Lucide-style) by name. Inline SVGs keep
// the UI fully offline and crisp at any size.
func icon(name string) string {
	const open = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" class="i">`
	paths := map[string]string{
		"dashboard": `<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>`,
		"history":   `<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 2"/>`,
		"clock":     `<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>`,
		"modules":   `<path d="M12 2 4 6v6l8 4 8-4V6z"/><path d="m4 6 8 4 8-4"/><path d="M12 10v10"/>`,
		"health":    `<path d="M3 12h4l2 5 4-12 2 7h6"/>`,
		"target":    `<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.5"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>`,
		"sparkle":   `<path d="M12 3v6M12 15v6M3 12h6M15 12h6"/><path d="m6 6 3 3M15 15l3 3M18 6l-3 3M9 15l-3 3"/>`,
		"download":  `<path d="M12 3v12"/><path d="m7 11 5 5 5-5"/><path d="M5 21h14"/>`,
		"plus":      `<path d="M12 5v14M5 12h14"/>`,
		"alert":     `<path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>`,
		"check":     `<path d="M20 6 9 17l-5-5"/>`,
		"calendar":  `<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 2v4M16 2v4"/><path d="M12 13v3l2 1"/>`,
		"chevron":   `<path d="m9 6 6 6-6 6"/>`,
		"shield":    `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,
		"globe":     `<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>`,
		"send":      `<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>`,
	}
	p, ok := paths[name]
	if !ok {
		p = paths["shield"]
	}
	return open + p + `</svg>`
}

// humanizeValue renders any JSON-ish value as HTML.
func humanizeValue(v any, depth int) string {
	switch t := v.(type) {
	case nil:
		return `<span class="empty">—</span>`
	case bool:
		if t {
			return `<span class="badge sev-low">yes</span>`
		}
		return `<span class="badge sev-info">no</span>`
	case string:
		return scalarString(t)
	case float64:
		return fmt.Sprintf(`<span class="mono">%s</span>`, html.EscapeString(trimNum(t)))
	case int, int64:
		return fmt.Sprintf(`<span class="mono">%v</span>`, t)
	case []any:
		return humanizeSlice(t, depth)
	case map[string]any:
		return humanizeMap(t, depth)
	default:
		return html.EscapeString(fmt.Sprint(t))
	}
}

func scalarString(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return `<span class="empty">—</span>`
	}
	switch strings.ToLower(trimmed) {
	case "critical", "high", "medium", "low", "info":
		return severityBadge(trimmed)
	}
	esc := html.EscapeString(trimmed)
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return fmt.Sprintf(`<a href="%s" target="_blank" rel="noreferrer noopener">%s</a>`, esc, esc)
	}
	return esc
}

func humanizeSlice(arr []any, depth int) string {
	if len(arr) == 0 {
		return `<span class="empty">none</span>`
	}
	// Array of objects -> table.
	if _, ok := arr[0].(map[string]any); ok && depth < 4 {
		return humanizeTable(arr, depth)
	}
	// Array of scalars -> chips (capped).
	var b strings.Builder
	limit := 60
	for i, e := range arr {
		if i >= limit {
			fmt.Fprintf(&b, `<span class="dim">+%d more</span>`, len(arr)-limit)
			break
		}
		fmt.Fprintf(&b, `<span class="chip mono">%s</span>`, stripTags(humanizeValue(e, depth+1)))
	}
	return b.String()
}

// humanizeTable renders an array of objects as a table with a stable column set.
func humanizeTable(arr []any, depth int) string {
	var cols []string
	seen := map[string]bool{}
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			for _, k := range orderedKeys(m) {
				if !seen[k] && !strings.HasPrefix(k, "_") {
					seen[k] = true
					cols = append(cols, k)
				}
			}
		}
	}
	if len(cols) == 0 {
		return `<span class="empty">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<div style="overflow:auto"><table class="tbl"><thead><tr>`)
	for _, c := range cols {
		fmt.Fprintf(&b, `<th>%s</th>`, html.EscapeString(prettifyKey(c)))
	}
	b.WriteString(`</tr></thead><tbody>`)
	limit := 40
	for i, e := range arr {
		if i >= limit {
			fmt.Fprintf(&b, `<tr><td colspan="%d" class="dim">+%d more rows</td></tr>`, len(cols), len(arr)-limit)
			break
		}
		m, _ := e.(map[string]any)
		b.WriteString("<tr>")
		for _, c := range cols {
			fmt.Fprintf(&b, `<td>%s</td>`, humanizeValue(m[c], depth+1))
		}
		b.WriteString("</tr>")
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// humanizeMap renders an object as a key/value spec list.
func humanizeMap(m map[string]any, depth int) string {
	keys := orderedKeys(m)
	if len(keys) == 0 {
		return `<span class="empty">—</span>`
	}
	var b strings.Builder
	b.WriteString(`<div class="spec">`)
	for _, k := range keys {
		if strings.HasPrefix(k, "_") && k != "_error" {
			continue
		}
		label := prettifyKey(k)
		if k == "_error" {
			label = "Error"
		}
		fmt.Fprintf(&b, `<div class="k">%s</div><div class="v">%s</div>`,
			html.EscapeString(label), humanizeValue(m[k], depth+1))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// orderedKeys sorts keys with important ones first, then alphabetical.
func orderedKeys(m map[string]any) []string {
	priority := map[string]int{
		"severity": 0, "overall_severity": 0, "status": 1, "risk_assessment": 2,
		"grade": 3, "score": 4, "name": 5, "title": 5, "url": 6, "domain": 6,
		"ip": 6, "vulnerable": 1, "present": 1, "waf_detected": 1,
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		pi, oki := priority[keys[i]]
		pj, okj := priority[keys[j]]
		if oki && okj {
			if pi != pj {
				return pi < pj
			}
			return keys[i] < keys[j]
		}
		if oki != okj {
			return oki
		}
		return keys[i] < keys[j]
	})
	return keys
}

// prettifyKey turns snake_case into a Title Case label, fixing common acronyms.
func prettifyKey(k string) string {
	if k == "" {
		return ""
	}
	parts := strings.FieldsFunc(k, func(r rune) bool { return r == '_' || r == '-' })
	acr := map[string]string{
		"ip": "IP", "dns": "DNS", "tls": "TLS", "ssl": "SSL", "url": "URL", "uri": "URI",
		"cve": "CVE", "id": "ID", "isp": "ISP", "asn": "ASN", "cn": "CN", "mx": "MX",
		"ns": "NS", "txt": "TXT", "spf": "SPF", "dmarc": "DMARC", "waf": "WAF", "cdn": "CDN",
		"md5": "MD5", "os": "OS", "ca": "CA", "ttl": "TTL", "rpm": "RPM", "api": "API",
		"http": "HTTP", "soa": "SOA", "sans": "SANs", "otx": "OTX", "vt": "VT",
	}
	for i, p := range parts {
		if a, ok := acr[strings.ToLower(p)]; ok {
			parts[i] = a
		} else {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func severityBadge(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return fmt.Sprintf(`<span class="badge dot sev-%s">%s</span>`, s, html.EscapeString(sev))
	default:
		return html.EscapeString(sev)
	}
}

// gaugeVar returns CSS custom properties for the risk ring.
func gaugeVar(score int) template.CSS {
	ring := "#30a46c" // ok / green
	switch {
	case score >= 75:
		ring = "#e5484d" // critical
	case score >= 50:
		ring = "#ef7234" // high
	case score >= 25:
		ring = "#d8a01e" // medium
	case score > 0:
		ring = "#4c82f7" // low
	}
	return template.CSS(fmt.Sprintf("--val:%d;--ring:%s", score, ring))
}

func trimNum(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

func stripTags(s string) string {
	// Cheap tag strip for embedding humanized scalars inside chips.
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			break
		}
		s = s[:i] + s[i+j+1:]
	}
	return s
}
