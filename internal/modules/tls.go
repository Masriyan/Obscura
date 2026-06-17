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

// tlsModule ports modules/tls_info.py (name "tls"): basic certificate info.
type tlsModule struct{}

func init() { engine.Register(tlsModule{}) }

func (tlsModule) Name() string           { return "tls" }
func (tlsModule) Description() string    { return "Basic TLS certificate information retrieval." }
func (tlsModule) Category() string       { return "recon" }
func (tlsModule) Dependencies() []string { return nil }
func (tlsModule) RequiredKey() string    { return "" }
func (tlsModule) RateLimitRPM() int      { return 0 }

func (tlsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	if domain == "" {
		return nil, fmt.Errorf("no host in target")
	}

	dialer := safety.NewDialer(cfg.AllowInternal)
	dialer.Timeout = 10 * time.Second
	addr := net.JoinHostPort(domain, "443")

	verified := true
	conn, err := dialTLS(ctx, dialer, addr, &tls.Config{ServerName: domain})
	if err != nil {
		// Retry without verification to still surface cert details (mirrors original).
		verified = false
		conn, err = dialTLS(ctx, dialer, addr, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
		if err != nil {
			return map[string]any{"error": err.Error()}, nil
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	res := map[string]any{
		"subject":    map[string]any{},
		"issuer":     map[string]any{},
		"not_before": "N/A",
		"not_after":  "N/A",
		"protocol":   tlsVersionName(state.Version),
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		res["subject"] = map[string]any{
			"commonName":   leaf.Subject.CommonName,
			"organization": leaf.Subject.Organization,
		}
		res["issuer"] = map[string]any{
			"commonName":   leaf.Issuer.CommonName,
			"organization": leaf.Issuer.Organization,
		}
		res["not_before"] = leaf.NotBefore.Format("Jan  2 15:04:05 2006 MST")
		res["not_after"] = leaf.NotAfter.Format("Jan  2 15:04:05 2006 MST")
	}
	if !verified {
		res["warning"] = "Certificate chain could not be verified against system CA store"
	}
	return res, nil
}

func dialTLS(ctx context.Context, dialer *net.Dialer, addr string, cfg *tls.Config) (*tls.Conn, error) {
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, cfg)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
