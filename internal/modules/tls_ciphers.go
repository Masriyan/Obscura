package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// tlsCiphersModule enumerates supported TLS protocols and cipher suites (name
// "tls_ciphers") and flags weak/deprecated ones — a testssl-lite, no API.
type tlsCiphersModule struct{}

func init() { engine.Register(tlsCiphersModule{}) }

func (tlsCiphersModule) Name() string { return "tls_ciphers" }
func (tlsCiphersModule) Description() string {
	return "Enumerates supported TLS versions and cipher suites; flags TLS 1.0/1.1, weak ciphers, and missing forward secrecy."
}
func (tlsCiphersModule) Category() string       { return "recon" }
func (tlsCiphersModule) Dependencies() []string { return nil }
func (tlsCiphersModule) RequiredKey() string    { return "" }
func (tlsCiphersModule) RateLimitRPM() int      { return 0 }

var tlsVersions = []struct {
	name string
	ver  uint16
	weak bool
}{
	{"TLSv1.0", tls.VersionTLS10, true},
	{"TLSv1.1", tls.VersionTLS11, true},
	{"TLSv1.2", tls.VersionTLS12, false},
	{"TLSv1.3", tls.VersionTLS13, false},
}

func (tlsCiphersModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	addr := net.JoinHostPort(domain, "443")
	dialer := safety.NewDialer(cfg.AllowInternal)
	dialer.Timeout = 8 * time.Second

	protocols := map[string]bool{}
	findings := []map[string]any{}
	supportedVers := []uint16{}
	for _, v := range tlsVersions {
		if ctx.Err() != nil {
			break
		}
		ok := tlsHandshakeOK(ctx, dialer, addr, &tls.Config{
			ServerName: domain, InsecureSkipVerify: true, MinVersion: v.ver, MaxVersion: v.ver,
		})
		protocols[v.name] = ok
		if ok {
			supportedVers = append(supportedVers, v.ver)
			if v.weak {
				findings = append(findings, map[string]any{
					"name": v.name + " enabled", "severity": "medium",
					"description": v.name + " is deprecated and should be disabled.",
				})
			}
		}
	}
	if !protocols["TLSv1.3"] {
		findings = append(findings, map[string]any{
			"name": "TLS 1.3 not supported", "severity": "low",
			"description": "Server does not offer modern TLS 1.3.",
		})
	}

	// Cipher enumeration for TLS 1.2 (TLS 1.3 cipher suites are fixed/strong).
	accepted := []map[string]any{}
	weakCiphers := []string{}
	hasPFS := false
	all := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, cs := range all {
		if ctx.Err() != nil {
			break
		}
		if !supportsTLS12(cs.SupportedVersions) {
			continue
		}
		ok := tlsHandshakeOK(ctx, dialer, addr, &tls.Config{
			ServerName: domain, InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{cs.ID},
		})
		if !ok {
			continue
		}
		insecure := isInsecureCipher(cs.ID)
		accepted = append(accepted, map[string]any{"name": cs.Name, "insecure": insecure})
		if insecure {
			weakCiphers = append(weakCiphers, cs.Name)
		}
		if isPFS(cs.Name) {
			hasPFS = true
		}
	}
	if len(weakCiphers) > 0 {
		findings = append(findings, map[string]any{
			"name": fmt.Sprintf("%d weak cipher suite(s) accepted", len(weakCiphers)), "severity": "high",
			"description": "Server accepts insecure ciphers: " + joinMax(weakCiphers, 5),
		})
	}
	if len(accepted) > 0 && !hasPFS {
		findings = append(findings, map[string]any{
			"name": "No forward secrecy", "severity": "medium",
			"description": "No ECDHE/DHE cipher accepted on TLS 1.2 — sessions lack forward secrecy.",
		})
	}

	overall := "info"
	for _, f := range findings {
		if f["severity"] == "high" {
			overall = "high"
		} else if overall == "info" && (f["severity"] == "medium") {
			overall = "medium"
		}
	}
	return map[string]any{
		"host":             domain,
		"protocols":        protocols,
		"accepted_ciphers": accepted,
		"weak_ciphers":     weakCiphers,
		"forward_secrecy":  hasPFS,
		"findings":         findings,
		"overall_severity": overall,
	}, nil
}

func tlsHandshakeOK(ctx context.Context, dialer *net.Dialer, addr string, cfg *tls.Config) bool {
	conn, err := dialTLS(ctx, dialer, addr, cfg)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func supportsTLS12(vers []uint16) bool {
	for _, v := range vers {
		if v == tls.VersionTLS12 {
			return true
		}
	}
	return len(vers) == 0
}

func isInsecureCipher(id uint16) bool {
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == id {
			return true
		}
	}
	return false
}

func isPFS(name string) bool {
	return contains(name, "ECDHE") || contains(name, "DHE")
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func joinMax(s []string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
