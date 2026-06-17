// Package export renders scan results into downstream formats: CSV, STIX 2.1,
// and the SIEM dialects Splunk-CIM, QRadar-LEEF, and Elastic-ECS. Each exporter
// consumes the same normalized Finding list extracted from a scan's results map.
package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Finding is the normalized unit every exporter consumes.
type Finding struct {
	Module      string `json:"module"`
	Title       string `json:"title"`
	Severity    string `json:"severity"` // critical|high|medium|low|info
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Scan is the minimal scan envelope the exporters need.
type Scan struct {
	ID       int64
	Target   string
	ScanDate time.Time
	Results  map[string]any
}

// ExtractFindings normalizes severity-bearing items out of every module's data.
// It understands the common shapes used across modules (findings[], issues[],
// interesting_urls[], related_hosts[], plus a module-level overall_severity).
func ExtractFindings(results map[string]any) []Finding {
	var out []Finding
	names := make([]string, 0, len(results))
	for k := range results {
		if k != "_meta" && k != "_summary" {
			names = append(names, k)
		}
	}
	sort.Strings(names)

	for _, mod := range names {
		data, ok := results[mod].(map[string]any)
		if !ok {
			continue
		}
		before := len(out)
		// findings[] (http_probe, google_dorking, sec_headers)
		out = append(out, fromList(mod, data["findings"], "name", "description")...)
		// issues[] (ssl_chain)
		out = append(out, fromList(mod, data["issues"], "issue", "detail")...)
		// interesting_urls[] (wayback_urls)
		out = append(out, fromList(mod, data["interesting_urls"], "url", "url")...)

		// Module-level severity (e.g. dns_zone_transfer) — only when the module
		// did not already contribute itemized findings, to avoid double-counting.
		if len(out) == before {
			if sev := str(data["overall_severity"]); sev != "" && sev != "info" {
				out = append(out, Finding{Module: mod, Title: mod + " overall", Severity: sev, Description: str(data["risk_assessment"])})
			} else if sev := str(data["severity"]); sev != "" && sev != "info" {
				out = append(out, Finding{Module: mod, Title: mod + " overall", Severity: sev, Description: str(data["risk_assessment"])})
			}
		}
	}
	if out == nil {
		out = []Finding{}
	}
	return out
}

func fromList(mod string, v any, titleKey, descKey string) []Finding {
	// Accept both []any (results reparsed from JSON) and []map[string]any
	// (native Go module output, before any JSON round-trip).
	var arr []map[string]any
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				arr = append(arr, m)
			}
		}
	case []map[string]any:
		arr = t
	default:
		return nil
	}
	var out []Finding
	for _, m := range arr {
		sev := str(m["severity"])
		if sev == "" {
			sev = "info"
		}
		out = append(out, Finding{
			Module:      mod,
			Title:       firstNonEmpty(str(m[titleKey]), str(m["title"]), mod),
			Severity:    sev,
			Description: str(m[descKey]),
			URL:         str(m["url"]),
		})
	}
	return out
}

// CSV renders findings as a spreadsheet-friendly CSV.
func CSV(sc Scan) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"scan_id", "target", "scan_date", "module", "severity", "title", "description", "url"})
	for _, f := range ExtractFindings(sc.Results) {
		_ = w.Write([]string{
			fmt.Sprint(sc.ID), sc.Target, sc.ScanDate.Format(time.RFC3339),
			f.Module, f.Severity, f.Title, f.Description, f.URL,
		})
	}
	w.Flush()
	return buf.Bytes()
}

// STIX renders a STIX 2.1 bundle of indicator/observed-data-ish objects.
func STIX(sc Scan) []byte {
	now := time.Now().UTC().Format(time.RFC3339)
	objects := []map[string]any{
		{
			"type": "identity", "spec_version": "2.1",
			"id": "identity--obscura-scan", "name": "Obscura Scan",
			"identity_class": "system", "created": now, "modified": now,
		},
	}
	for i, f := range ExtractFindings(sc.Results) {
		objects = append(objects, map[string]any{
			"type":         "indicator",
			"spec_version": "2.1",
			"id":           fmt.Sprintf("indicator--obscura-%d-%d", sc.ID, i),
			"created":      now, "modified": now,
			"name":            f.Title,
			"description":     f.Description,
			"indicator_types": []string{severityToSTIX(f.Severity)},
			"pattern":         fmt.Sprintf("[url:value = '%s']", escapeSTIX(firstNonEmpty(f.URL, sc.Target))),
			"pattern_type":    "stix",
			"valid_from":      now,
			"labels":          []string{f.Module, f.Severity},
		})
	}
	bundle := map[string]any{
		"type": "bundle", "id": fmt.Sprintf("bundle--obscura-scan-%d", sc.ID), "objects": objects,
	}
	b, _ := json.MarshalIndent(bundle, "", "  ")
	return b
}

// SplunkCIM renders newline-delimited JSON aligned to Splunk's CIM fields.
func SplunkCIM(sc Scan) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, f := range ExtractFindings(sc.Results) {
		_ = enc.Encode(map[string]any{
			"time":      sc.ScanDate.Unix(),
			"vendor":    "Obscura Scan",
			"product":   "Obscura Scan",
			"dest":      sc.Target,
			"signature": f.Title,
			"severity":  f.Severity,
			"category":  f.Module,
			"url":       f.URL,
			"desc":      f.Description,
		})
	}
	return buf.Bytes()
}

// QRadarLEEF renders QRadar LEEF 2.0 events (one per line).
func QRadarLEEF(sc Scan) []byte {
	var b strings.Builder
	for _, f := range ExtractFindings(sc.Results) {
		// LEEF:2.0|Vendor|Product|Version|EventID|key=value\t...
		fmt.Fprintf(&b, "LEEF:2.0|Obscura Scan|Obscura Scan|9.0.0|%s|sev=%s\tcat=%s\tdst=%s\turl=%s\tmsg=%s\n",
			leefSanitize(f.Title), leefSeverity(f.Severity), leefSanitize(f.Module),
			leefSanitize(sc.Target), leefSanitize(f.URL), leefSanitize(f.Description))
	}
	return []byte(b.String())
}

// ElasticECS renders newline-delimited JSON aligned to the Elastic Common Schema.
func ElasticECS(sc Scan) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, f := range ExtractFindings(sc.Results) {
		_ = enc.Encode(map[string]any{
			"@timestamp": sc.ScanDate.UTC().Format(time.RFC3339),
			"ecs":        map[string]any{"version": "8.0.0"},
			"event": map[string]any{
				"kind": "alert", "category": []string{"threat"},
				"module": f.Module, "severity": ecsSeverity(f.Severity), "reason": f.Description,
			},
			"observer":    map[string]any{"vendor": "Obscura Scan", "product": "Obscura Scan"},
			"url":         map[string]any{"full": firstNonEmpty(f.URL, sc.Target)},
			"message":     f.Title,
			"destination": map[string]any{"domain": sc.Target},
		})
	}
	return buf.Bytes()
}

// ---- helpers ----

func severityToSTIX(sev string) string {
	switch sev {
	case "critical", "high":
		return "malicious-activity"
	default:
		return "anomalous-activity"
	}
}

func leefSeverity(sev string) string {
	switch sev {
	case "critical":
		return "10"
	case "high":
		return "8"
	case "medium":
		return "5"
	case "low":
		return "3"
	default:
		return "1"
	}
}

func ecsSeverity(sev string) int {
	switch sev {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 1
	}
}

func leefSanitize(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "/")
	return s
}

func escapeSTIX(s string) string { return strings.ReplaceAll(s, "'", "\\'") }

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
