package modules

import (
	"context"
	"net"
	"strings"
	"time"

	jarm "github.com/hdm/jarm-go"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// jarmModule computes the JARM active TLS server fingerprint (name
// "jarm_fingerprint") — useful for spotting shared infrastructure and C2.
type jarmModule struct{}

func init() { engine.Register(jarmModule{}) }

func (jarmModule) Name() string { return "jarm_fingerprint" }
func (jarmModule) Description() string {
	return "Active JARM TLS server fingerprint — identifies server TLS stack/config (shared infra, C2 hunting)."
}
func (jarmModule) Category() string       { return "recon" }
func (jarmModule) Dependencies() []string { return nil }
func (jarmModule) RequiredKey() string    { return "" }
func (jarmModule) RateLimitRPM() int      { return 0 }

func (jarmModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	host := target.Host
	const port = 443
	addr := net.JoinHostPort(host, "443")
	dialer := safety.NewDialer(cfg.AllowInternal)
	dialer.Timeout = 6 * time.Second

	var parts []string
	for _, probe := range jarm.GetProbes(host, port) {
		if ctx.Err() != nil {
			break
		}
		part := probeOnce(ctx, dialer, addr, probe)
		parts = append(parts, part)
	}

	fp := jarm.RawHashToFuzzyHash(strings.Join(parts, ","))
	res := map[string]any{"host": host, "jarm": fp}
	if fp == "" || fp == jarm.ZeroHash {
		res["jarm"] = jarm.ZeroHash
		res["responsive"] = false
		res["note"] = "No TLS response on 443 (JARM is all-zero)."
	} else {
		res["responsive"] = true
		res["pivot_query"] = "Search Shodan/Censys for ssl.jarm:" + fp + " to find related hosts."
	}
	return res, nil
}

func probeOnce(ctx context.Context, dialer *net.Dialer, addr string, probe jarm.JarmProbeOptions) string {
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	deadline := time.Now().Add(6 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(jarm.BuildProbe(probe)); err != nil {
		return ""
	}
	buf := make([]byte, 1484)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	ans, err := jarm.ParseServerHello(buf[:n], probe)
	if err != nil {
		return ""
	}
	return ans
}
