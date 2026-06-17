package modules

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// sslChainModule ports modules/ssl_chain.py (name "ssl_chain"): deep certificate
// chain analysis — leaf checks, wildcard/CA trust, chain integrity, scoring.
type sslChainModule struct{}

func init() { engine.Register(sslChainModule{}) }

func (sslChainModule) Name() string { return "ssl_chain" }
func (sslChainModule) Description() string {
	return "Deep SSL certificate chain analysis — intermediate validation, wildcard abuse, CA trust scoring."
}
func (sslChainModule) Category() string       { return "recon" }
func (sslChainModule) Dependencies() []string { return nil }
func (sslChainModule) RequiredKey() string    { return "" }
func (sslChainModule) RateLimitRPM() int      { return 0 }

var trustedCAs = map[string]struct{ trust, typ string }{
	"digicert":              {"high", "enterprise"},
	"let's encrypt":         {"medium", "free"},
	"comodo":                {"high", "enterprise"},
	"sectigo":               {"high", "enterprise"},
	"globalsign":            {"high", "enterprise"},
	"entrust":               {"high", "enterprise"},
	"verisign":              {"high", "enterprise"},
	"geotrust":              {"high", "enterprise"},
	"amazon":                {"high", "cloud"},
	"google trust services": {"high", "cloud"},
	"cloudflare":            {"medium", "cdn"},
	"buypass":               {"medium", "free"},
	"zerossl":               {"medium", "free"},
}

func (sslChainModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	res := map[string]any{
		"domain": domain, "chain": []any{}, "chain_length": 0, "chain_valid": false,
		"leaf_cert": map[string]any{}, "issues": []any{}, "score": 100, "grade": "A",
	}

	dialer := safety.NewDialer(cfg.AllowInternal)
	dialer.Timeout = 10 * time.Second
	conn, err := dialTLS(ctx, dialer, net.JoinHostPort(domain, "443"), &tls.Config{ServerName: domain, InsecureSkipVerify: true})
	if err != nil {
		res["error"] = "Could not connect or retrieve SSL certificate"
		res["grade"] = "F"
		res["score"] = 0
		return res, nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		res["error"] = "No certificate presented"
		res["grade"] = "F"
		res["score"] = 0
		return res, nil
	}

	// Verified-chain validity (best effort against system roots).
	valid := false
	if _, verr := certs[0].Verify(x509.VerifyOptions{DNSName: domain, Intermediates: intermediatePool(certs)}); verr == nil {
		valid = true
	}

	chain := make([]any, 0, len(certs))
	for i, c := range certs {
		chain = append(chain, certInfo(c, i))
	}
	leaf := certs[0]
	leafInfo := certInfo(leaf, 0).(map[string]any)
	sans := leaf.DNSNames
	leafInfo["sans"] = sans

	score := 100
	issues := []any{}

	// Expiry.
	daysRemaining := int(time.Until(leaf.NotAfter).Hours() / 24)
	switch {
	case daysRemaining <= 0:
		issues = append(issues, issue("critical", "Certificate has EXPIRED", "expired"))
		score -= 50
	case daysRemaining <= 7:
		issues = append(issues, issue("high", "Certificate expires in less than 7 days", ""))
		score -= 20
	case daysRemaining <= 30:
		issues = append(issues, issue("medium", "Certificate expires soon", ""))
		score -= 5
	}

	// Validity period.
	validityDays := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	if validityDays > 398 {
		issues = append(issues, issue("medium", "Certificate validity exceeds recommended 13 months", ""))
	}

	// Wildcards.
	var wildcards []string
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			wildcards = append(wildcards, s)
		}
	}
	if len(wildcards) > 3 {
		issues = append(issues, issue("medium", "Excessive wildcard SANs", ""))
		score -= 5
	}
	if len(sans) > 50 {
		issues = append(issues, issue("medium", "Large number of SANs (shared hosting/CDN)", ""))
	}

	// CA trust.
	issuerOrg := strings.ToLower(strings.Join(leaf.Issuer.Organization, " "))
	issuerCN := strings.ToLower(leaf.Issuer.CommonName)
	trust := "unknown"
	for ca, info := range trustedCAs {
		if strings.Contains(issuerOrg, ca) || strings.Contains(issuerCN, ca) {
			trust = info.trust
			leafInfo["ca_type"] = info.typ
			break
		}
	}
	leafInfo["ca_trust"] = trust
	if trust == "unknown" {
		issues = append(issues, issue("low", "Certificate issued by less common CA", issuerOrg))
	}

	// Chain integrity.
	if len(certs) == 1 {
		issues = append(issues, issue("medium", "Self-signed or missing intermediate certificates", ""))
		score -= 10
	}

	res["chain"] = chain
	res["chain_length"] = len(certs)
	res["chain_valid"] = valid
	res["leaf_cert"] = leafInfo
	res["issues"] = issues
	res["score"] = score
	res["grade"] = sslGrade(score)
	return res, nil
}

func certInfo(c *x509.Certificate, pos int) any {
	return map[string]any{
		"position":       pos,
		"subject_cn":     c.Subject.CommonName,
		"issuer_cn":      c.Issuer.CommonName,
		"issuer_org":     strings.Join(c.Issuer.Organization, ", "),
		"not_before":     c.NotBefore.Format("Jan  2 15:04:05 2006 MST"),
		"not_after":      c.NotAfter.Format("Jan  2 15:04:05 2006 MST"),
		"validity_days":  int(c.NotAfter.Sub(c.NotBefore).Hours() / 24),
		"days_remaining": int(time.Until(c.NotAfter).Hours() / 24),
		"serial":         c.SerialNumber.String(),
		"version":        c.Version,
	}
}

func intermediatePool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs[1:] {
		pool.AddCert(c)
	}
	return pool
}

func issue(sev, text, detail string) map[string]any {
	m := map[string]any{"severity": sev, "issue": text}
	if detail != "" {
		m["detail"] = detail
	}
	return m
}

func sslGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
