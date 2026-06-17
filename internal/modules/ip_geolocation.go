package modules

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sort"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// ipGeoModule ports modules/ip_geolocation.py (name "ip_geolocation"): resolves
// target IPs and enriches via ip-api.com (free, no key) with provider detection.
type ipGeoModule struct{}

func init() { engine.Register(ipGeoModule{}) }

func (ipGeoModule) Name() string { return "ip_geolocation" }
func (ipGeoModule) Description() string {
	return "Resolves target IPs and enriches each with geolocation, ISP, ASN, and cloud/CDN provider detection — no API key required."
}
func (ipGeoModule) Category() string       { return "intel" }
func (ipGeoModule) Dependencies() []string { return nil }
func (ipGeoModule) RequiredKey() string    { return "" }
func (ipGeoModule) RateLimitRPM() int      { return 45 }

var cloudKeywords = map[string][]string{
	"Amazon AWS":      {"amazon", "aws ", "ec2.", "cloudfront"},
	"Google Cloud":    {"google llc", "google cloud", "gcp"},
	"Microsoft Azure": {"microsoft", "azure"},
	"Cloudflare":      {"cloudflare"},
	"Fastly":          {"fastly"},
	"Akamai":          {"akamai"},
	"DigitalOcean":    {"digitalocean"},
	"Linode/Akamai":   {"linode"},
	"Vultr":           {"vultr"},
	"Hetzner":         {"hetzner"},
	"OVH":             {"ovh "},
	"Alibaba Cloud":   {"alibaba", "alicloud", "aliyun"},
	"Oracle Cloud":    {"oracle"},
}

type geoResp struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Timezone    string  `json:"timezone"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Query       string  `json:"query"`
}

func (ipGeoModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	domain := target.Host
	ips := resolvePublicIPs(domain)
	if len(ips) == 0 {
		return map[string]any{"error": "Could not resolve any routable IPs for " + domain, "domain": domain}, nil
	}
	sort.Strings(ips)
	if len(ips) > 5 {
		ips = ips[:5]
	}

	res := map[string]any{"domain": domain, "resolved_ips": ips, "geolocations": []any{}, "summary": map[string]any{}, "risk": map[string]any{}}
	var geos []geoResp
	for _, ip := range ips {
		if g, ok := geolocate(ctx, client, ip); ok {
			geos = append(geos, g)
		}
	}
	geoMaps := make([]any, 0, len(geos))
	for _, g := range geos {
		geoMaps = append(geoMaps, g)
	}
	res["geolocations"] = geoMaps
	if len(geos) == 0 {
		return res, nil
	}

	primary := geos[0]
	provider := detectProvider(primary)
	res["summary"] = map[string]any{
		"primary_ip": primary.Query, "country": primary.Country, "country_code": primary.CountryCode,
		"region": primary.RegionName, "city": primary.City, "isp": primary.ISP, "org": primary.Org,
		"asn": primary.AS, "timezone": primary.Timezone, "lat": primary.Lat, "lon": primary.Lon,
		"provider": provider, "hosting_type": classifyHosting(primary, provider),
		"is_proxy": primary.Proxy, "is_hosting": primary.Hosting,
	}

	countrySet := map[string]bool{}
	flags := []string{}
	for _, g := range geos {
		if g.Country != "" {
			countrySet[g.Country] = true
		}
		if g.Proxy {
			flags = append(flags, "One or more IPs are flagged as proxy/VPN exit nodes.")
		}
	}
	res["countries"] = keys(countrySet)
	level := "info"
	if len(countrySet) > 1 {
		flags = append(flags, "Target resolves to IPs in multiple countries.")
	}
	if len(flags) > 0 {
		level = "medium"
	}
	msg := "Hosted in " + primary.Country + " via " + primary.ISP
	if provider != "Unknown" {
		msg += " (" + provider + ")"
	}
	res["risk"] = map[string]any{"level": level, "message": msg, "flags": flags}
	return res, nil
}

func resolvePublicIPs(domain string) []string {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && !safety.IsBlockedIP(ip) {
			out = append(out, a)
		}
	}
	return out
}

func geolocate(ctx context.Context, client *httpx.Client, ip string) (geoResp, bool) {
	url := "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting,query"
	resp, err := client.Get(ctx, url)
	if err != nil {
		return geoResp{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var g geoResp
	if err := json.Unmarshal(body, &g); err != nil || g.Status != "success" {
		return geoResp{}, false
	}
	return g, true
}

func detectProvider(g geoResp) string {
	combined := strings.ToLower(g.Org + " " + g.ISP)
	for provider, kws := range cloudKeywords {
		for _, kw := range kws {
			if strings.Contains(combined, kw) {
				return provider
			}
		}
	}
	return "Unknown"
}

func classifyHosting(g geoResp, provider string) string {
	if g.Proxy {
		return "Proxy / VPN"
	}
	if provider != "Unknown" {
		return "Cloud — " + provider
	}
	if g.Hosting {
		return "Hosting / Datacenter"
	}
	return "Dedicated Server"
}
