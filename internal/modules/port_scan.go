package modules

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// portScanModule does a light TCP-connect scan of common ports (name
// "port_scan"), through the SSRF-guarded dialer. It is opt-in (semi-offensive).
type portScanModule struct{}

func init() { engine.Register(portScanModule{}) }

func (portScanModule) Name() string { return "port_scan" }
func (portScanModule) Description() string {
	return "Light TCP connect scan of common service ports; flags risky exposed services."
}
func (portScanModule) Category() string       { return "semi-offensive" }
func (portScanModule) Dependencies() []string { return nil }
func (portScanModule) RequiredKey() string    { return "" }
func (portScanModule) RateLimitRPM() int      { return 0 }

var commonPorts = map[int]struct{ service, severity string }{
	21:    {"FTP", "medium"},
	22:    {"SSH", "info"},
	23:    {"Telnet", "high"},
	25:    {"SMTP", "info"},
	53:    {"DNS", "info"},
	80:    {"HTTP", "info"},
	110:   {"POP3", "low"},
	135:   {"MSRPC", "medium"},
	139:   {"NetBIOS", "medium"},
	143:   {"IMAP", "low"},
	443:   {"HTTPS", "info"},
	445:   {"SMB", "high"},
	1433:  {"MSSQL", "high"},
	3306:  {"MySQL", "high"},
	3389:  {"RDP", "high"},
	5432:  {"PostgreSQL", "high"},
	5900:  {"VNC", "high"},
	6379:  {"Redis", "high"},
	8080:  {"HTTP-alt", "info"},
	8443:  {"HTTPS-alt", "info"},
	9200:  {"Elasticsearch", "high"},
	11211: {"Memcached", "high"},
	27017: {"MongoDB", "high"},
}

func (portScanModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	ip := resolveOneIP(target.Host)
	if ip == "" {
		return map[string]any{"error": "could not resolve a public IP for " + target.Host}, nil
	}

	dialer := safety.NewDialer(cfg.AllowInternal)
	type openPort struct {
		Port     int
		Service  string
		Severity string
	}
	var (
		mu   sync.Mutex
		open []openPort
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 20) // bounded concurrency
	)
	for port, meta := range commonPorts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(port int, service, severity string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(ip, itoa(port)))
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, openPort{port, service, severity})
			mu.Unlock()
		}(port, meta.service, meta.severity)
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	ports := make([]map[string]any, 0, len(open))
	findings := []map[string]any{}
	for _, p := range open {
		ports = append(ports, map[string]any{"port": p.Port, "service": p.Service, "severity": p.Severity})
		if p.Severity == "high" || p.Severity == "medium" {
			findings = append(findings, map[string]any{
				"name": p.Service + " exposed on port " + itoa(p.Port), "severity": p.Severity,
				"description": "Service reachable from the internet — restrict access if unintended.",
			})
		}
	}
	overall := "info"
	if len(findings) > 0 {
		overall = "medium"
		for _, f := range findings {
			if f["severity"] == "high" {
				overall = "high"
			}
		}
	}
	return map[string]any{
		"ip":               ip,
		"ports_scanned":    len(commonPorts),
		"open_ports":       ports,
		"open_count":       len(ports),
		"findings":         findings,
		"overall_severity": overall,
	}, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
