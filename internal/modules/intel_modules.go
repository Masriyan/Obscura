package modules

import (
	"context"
	"net"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/intel"
	"obscurascan/internal/safety"
)

// resolveOneIP returns the first public IP for a host, or "".
func resolveOneIP(host string) string {
	for _, a := range firstHostIPs(host) {
		if ip := net.ParseIP(a); ip != nil && !safety.IsBlockedIP(ip) {
			return a
		}
	}
	return ""
}

func firstHostIPs(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return addrs
}

// --- VirusTotal (domain reputation) ---

type virusTotalModule struct{}

func init() { engine.Register(virusTotalModule{}) }

func (virusTotalModule) Name() string { return "virustotal" }
func (virusTotalModule) Description() string {
	return "VirusTotal domain reputation — malicious/suspicious engine counts and categories."
}
func (virusTotalModule) Category() string       { return "intel" }
func (virusTotalModule) Dependencies() []string { return nil }
func (virusTotalModule) RequiredKey() string    { return "VT_API_KEY" }
func (virusTotalModule) RateLimitRPM() int      { return 4 }

func (virusTotalModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	data, err := intel.VirusTotalDomain(ctx, client, cfg.VTKey, target.Host)
	if err != nil {
		return map[string]any{"error": err.Error(), "domain": target.Host}, nil
	}
	mal, _ := data["malicious"].(int)
	if mal > 0 {
		data["severity"] = "high"
		data["risk_assessment"] = "Flagged malicious by VirusTotal engines."
	} else {
		data["severity"] = "info"
	}
	data["domain"] = target.Host
	return data, nil
}

// --- Shodan (host exposure) ---

type shodanModule struct{}

func init() { engine.Register(shodanModule{}) }

func (shodanModule) Name() string { return "shodan" }
func (shodanModule) Description() string {
	return "Shodan host exposure — open ports, banners, known vulns."
}
func (shodanModule) Category() string       { return "intel" }
func (shodanModule) Dependencies() []string { return nil }
func (shodanModule) RequiredKey() string    { return "SHODAN_API_KEY" }
func (shodanModule) RateLimitRPM() int      { return 60 }

func (shodanModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	ip := resolveOneIP(target.Host)
	if ip == "" {
		return map[string]any{"error": "could not resolve a public IP for " + target.Host}, nil
	}
	data, err := intel.ShodanHost(ctx, client, cfg.ShodanKey, ip)
	if err != nil {
		return map[string]any{"error": err.Error(), "ip": ip}, nil
	}
	if v, ok := data["vulns"]; ok && v != nil {
		data["severity"] = "high"
		data["risk_assessment"] = "Shodan reports known CVEs on this host."
	}
	return data, nil
}

// --- AbuseIPDB (IP reputation) ---

type abuseIPDBModule struct{}

func init() { engine.Register(abuseIPDBModule{}) }

func (abuseIPDBModule) Name() string { return "abuseipdb" }
func (abuseIPDBModule) Description() string {
	return "AbuseIPDB reputation — abuse confidence score and report count for the target IP."
}
func (abuseIPDBModule) Category() string       { return "intel" }
func (abuseIPDBModule) Dependencies() []string { return nil }
func (abuseIPDBModule) RequiredKey() string    { return "ABUSEIPDB_API_KEY" }
func (abuseIPDBModule) RateLimitRPM() int      { return 60 }

func (abuseIPDBModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	ip := resolveOneIP(target.Host)
	if ip == "" {
		return map[string]any{"error": "could not resolve a public IP for " + target.Host}, nil
	}
	data, err := intel.AbuseIPDB(ctx, client, cfg.AbuseIPDBKey, ip)
	if err != nil {
		return map[string]any{"error": err.Error(), "ip": ip}, nil
	}
	if score, ok := data["abuse_confidence"].(float64); ok {
		switch {
		case score >= 75:
			data["severity"] = "high"
		case score >= 25:
			data["severity"] = "medium"
		default:
			data["severity"] = "info"
		}
	}
	return data, nil
}

// --- GreyNoise (internet noise) ---

type greyNoiseModule struct{}

func init() { engine.Register(greyNoiseModule{}) }

func (greyNoiseModule) Name() string { return "greynoise" }
func (greyNoiseModule) Description() string {
	return "GreyNoise community lookup — is the IP a known internet scanner / benign service (RIOT)."
}
func (greyNoiseModule) Category() string       { return "intel" }
func (greyNoiseModule) Dependencies() []string { return nil }
func (greyNoiseModule) RequiredKey() string    { return "GREYNOISE_API_KEY" }
func (greyNoiseModule) RateLimitRPM() int      { return 60 }

func (greyNoiseModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	ip := resolveOneIP(target.Host)
	if ip == "" {
		return map[string]any{"error": "could not resolve a public IP for " + target.Host}, nil
	}
	data, err := intel.GreyNoise(ctx, client, cfg.GreyNoiseKey, ip)
	if err != nil {
		return map[string]any{"error": err.Error(), "ip": ip}, nil
	}
	return data, nil
}

// --- URLScan (public search, no key required) ---

type urlscanModule struct{}

func init() { engine.Register(urlscanModule{}) }

func (urlscanModule) Name() string { return "urlscan" }
func (urlscanModule) Description() string {
	return "URLScan.io public search — historical scans, resolved IPs, and servers for the domain."
}
func (urlscanModule) Category() string       { return "intel" }
func (urlscanModule) Dependencies() []string { return nil }
func (urlscanModule) RequiredKey() string    { return "" }
func (urlscanModule) RateLimitRPM() int      { return 60 }

func (urlscanModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	data, err := intel.URLScanSearch(ctx, client, target.Host)
	if err != nil {
		return map[string]any{"error": err.Error(), "domain": target.Host}, nil
	}
	data["domain"] = target.Host
	return data, nil
}

// --- AlienVault OTX (threat-feed pulses) ---

type otxModule struct{}

func init() { engine.Register(otxModule{}) }

func (otxModule) Name() string { return "otx" }
func (otxModule) Description() string {
	return "AlienVault OTX — number of threat-intel pulses referencing the domain."
}
func (otxModule) Category() string       { return "intel" }
func (otxModule) Dependencies() []string { return nil }
func (otxModule) RequiredKey() string    { return "OTX_API_KEY" }
func (otxModule) RateLimitRPM() int      { return 60 }

func (otxModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	data, err := intel.OTXDomain(ctx, client, cfg.OTXKey, target.Host)
	if err != nil {
		return map[string]any{"error": err.Error(), "domain": target.Host}, nil
	}
	if in, _ := data["in_threat_feeds"].(bool); in {
		data["severity"] = "medium"
		data["risk_assessment"] = "Domain appears in OTX threat-intel pulses."
	}
	return data, nil
}

// --- SecurityTrails (DNS history) ---

type securityTrailsModule struct{}

func init() { engine.Register(securityTrailsModule{}) }

func (securityTrailsModule) Name() string { return "securitytrails" }
func (securityTrailsModule) Description() string {
	return "SecurityTrails — current DNS data and historical A-record changes for the domain."
}
func (securityTrailsModule) Category() string       { return "intel" }
func (securityTrailsModule) Dependencies() []string { return nil }
func (securityTrailsModule) RequiredKey() string    { return "SECURITYTRAILS_API_KEY" }
func (securityTrailsModule) RateLimitRPM() int      { return 60 }

func (securityTrailsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	data, err := intel.SecurityTrails(ctx, client, cfg.SecurityTrailsKey, target.Host)
	if err != nil {
		return map[string]any{"error": err.Error(), "domain": target.Host}, nil
	}
	return data, nil
}
