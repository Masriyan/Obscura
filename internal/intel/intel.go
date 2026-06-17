// Package intel holds thin REST clients for third-party threat-intel APIs
// (VirusTotal, Shodan, GreyNoise, AbuseIPDB, URLScan, ...). Each is a simple
// HTTP+JSON call — no vendor SDKs — and reads its key from config. Endpoints
// and auth headers mirror the Python aegis.py helpers.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"obscurascan/internal/httpx"
)

// getJSON performs an authenticated GET and decodes the JSON body into out.
func getJSON(ctx context.Context, client *httpx.Client, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.RawDo(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return json.Unmarshal(body, out)
}

// VirusTotalDomain returns reputation stats for a domain via VT API v3.
func VirusTotalDomain(ctx context.Context, client *httpx.Client, key, domain string) (map[string]any, error) {
	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
				Reputation        int            `json:"reputation"`
				Categories        map[string]any `json:"categories"`
			} `json:"attributes"`
		} `json:"data"`
	}
	err := getJSON(ctx, client, "https://www.virustotal.com/api/v3/domains/"+url.PathEscape(domain),
		map[string]string{"x-apikey": key}, &raw)
	if err != nil {
		return nil, err
	}
	stats := raw.Data.Attributes.LastAnalysisStats
	return map[string]any{
		"reputation":     raw.Data.Attributes.Reputation,
		"malicious":      stats["malicious"],
		"suspicious":     stats["suspicious"],
		"harmless":       stats["harmless"],
		"undetected":     stats["undetected"],
		"categories":     raw.Data.Attributes.Categories,
		"analysis_stats": stats,
	}, nil
}

// ShodanHost returns host info for an IP via Shodan.
func ShodanHost(ctx context.Context, client *httpx.Client, key, ip string) (map[string]any, error) {
	var raw map[string]any
	err := getJSON(ctx, client, "https://api.shodan.io/shodan/host/"+ip+"?key="+url.QueryEscape(key), nil, &raw)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"ip":        ip,
		"ports":     raw["ports"],
		"hostnames": raw["hostnames"],
		"org":       raw["org"],
		"os":        raw["os"],
		"isp":       raw["isp"],
		"country":   raw["country_name"],
	}
	if v, ok := raw["vulns"]; ok {
		out["vulns"] = v
	}
	return out, nil
}

// GreyNoise returns community noise/RIOT classification for an IP.
func GreyNoise(ctx context.Context, client *httpx.Client, key, ip string) (map[string]any, error) {
	var raw map[string]any
	err := getJSON(ctx, client, "https://api.greynoise.io/v3/community/"+ip,
		map[string]string{"key": key}, &raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ip":             ip,
		"noise":          raw["noise"],
		"riot":           raw["riot"],
		"classification": raw["classification"],
		"name":           raw["name"],
		"last_seen":      raw["last_seen"],
	}, nil
}

// AbuseIPDB returns the abuse confidence score for an IP.
func AbuseIPDB(ctx context.Context, client *httpx.Client, key, ip string) (map[string]any, error) {
	var raw struct {
		Data map[string]any `json:"data"`
	}
	err := getJSON(ctx, client, "https://api.abuseipdb.com/api/v2/check?ipAddress="+url.QueryEscape(ip),
		map[string]string{"Key": key, "Accept": "application/json"}, &raw)
	if err != nil {
		return nil, err
	}
	d := raw.Data
	return map[string]any{
		"ip":               ip,
		"abuse_confidence": d["abuseConfidenceScore"],
		"total_reports":    d["totalReports"],
		"country_code":     d["countryCode"],
		"usage_type":       d["usageType"],
		"isp":              d["isp"],
		"domain":           d["domain"],
		"is_public":        d["isPublic"],
		"is_whitelisted":   d["isWhitelisted"],
		"last_reported_at": d["lastReportedAt"],
	}, nil
}

// URLScanSearch queries URLScan public search for a domain (no key required).
func URLScanSearch(ctx context.Context, client *httpx.Client, domain string) (map[string]any, error) {
	var raw struct {
		Total   int `json:"total"`
		Results []struct {
			Task struct {
				URL  string `json:"url"`
				Time string `json:"time"`
			} `json:"task"`
			Page struct {
				Domain string `json:"domain"`
				IP     string `json:"ip"`
				Server string `json:"server"`
			} `json:"page"`
		} `json:"results"`
	}
	err := getJSON(ctx, client, "https://urlscan.io/api/v1/search/?q=domain:"+url.QueryEscape(domain), nil, &raw)
	if err != nil {
		return nil, err
	}
	results := make([]map[string]any, 0, len(raw.Results))
	for i, r := range raw.Results {
		if i >= 20 {
			break
		}
		results = append(results, map[string]any{
			"url": r.Task.URL, "time": r.Task.Time,
			"domain": r.Page.Domain, "ip": r.Page.IP, "server": r.Page.Server,
		})
	}
	return map[string]any{"total": raw.Total, "results": results}, nil
}

// OTXDomain returns AlienVault OTX general info + pulse count for a domain.
func OTXDomain(ctx context.Context, client *httpx.Client, key, domain string) (map[string]any, error) {
	var raw struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
		Whois     string `json:"whois"`
		Alexa     string `json:"alexa"`
		Indicator string `json:"indicator"`
	}
	err := getJSON(ctx, client, "https://otx.alienvault.com/api/v1/indicators/domain/"+url.PathEscape(domain)+"/general",
		map[string]string{"X-OTX-API-KEY": key}, &raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"domain":          domain,
		"pulse_count":     raw.PulseInfo.Count,
		"in_threat_feeds": raw.PulseInfo.Count > 0,
		"alexa":           raw.Alexa,
	}, nil
}

// SecurityTrails returns current DNS + A-record history for a domain.
func SecurityTrails(ctx context.Context, client *httpx.Client, key, domain string) (map[string]any, error) {
	out := map[string]any{"domain": domain}
	var cur map[string]any
	if err := getJSON(ctx, client, "https://api.securitytrails.com/v1/domain/"+url.PathEscape(domain),
		map[string]string{"APIKEY": key}, &cur); err == nil {
		out["current"] = cur
	} else {
		out["current"] = map[string]any{"error": err.Error()}
	}
	var hist struct {
		Records []any `json:"records"`
	}
	if err := getJSON(ctx, client, "https://api.securitytrails.com/v1/history/"+url.PathEscape(domain)+"/dns/a",
		map[string]string{"APIKEY": key}, &hist); err == nil {
		recs := hist.Records
		if len(recs) > 25 {
			recs = recs[:25]
		}
		out["history"] = recs
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
