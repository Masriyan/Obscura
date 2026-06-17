package modules

import (
	"context"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// emailSecurityModule audits the full email-authentication posture beyond SPF
// (name "email_security"): DKIM selectors, DMARC, BIMI, MTA-STS, TLS-RPT,
// DNSSEC, and CAA — all via DNS, no API.
type emailSecurityModule struct{}

func init() { engine.Register(emailSecurityModule{}) }

func (emailSecurityModule) Name() string { return "email_security" }
func (emailSecurityModule) Description() string {
	return "Full email-auth posture: DKIM selectors, DMARC, BIMI, MTA-STS, TLS-RPT, DNSSEC, CAA (DNS only)."
}
func (emailSecurityModule) Category() string       { return "recon" }
func (emailSecurityModule) Dependencies() []string { return nil }
func (emailSecurityModule) RequiredKey() string    { return "" }
func (emailSecurityModule) RateLimitRPM() int      { return 0 }

var dkimSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "dkim", "mail",
	"smtp", "s1", "s2", "mandrill", "mailchimp", "sendgrid", "amazonses", "zoho", "protonmail", "fm1",
}

func (emailSecurityModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	res := map[string]any{"domain": domain}
	findings := []map[string]any{}

	// DMARC.
	dmarc := checkDMARC(ctx, domain)
	res["dmarc"] = dmarc
	if found, _ := dmarc["found"].(bool); !found {
		findings = append(findings, fnd("No DMARC record", "high", "Domain has no DMARC policy — spoofing protection is incomplete."))
	} else if dmarc["policy"] == "none" {
		findings = append(findings, fnd("DMARC policy is p=none", "medium", "DMARC is monitor-only; set p=quarantine or p=reject to enforce."))
	}

	// DKIM selectors.
	var dkim []string
	for _, sel := range dkimSelectors {
		if ctx.Err() != nil {
			break
		}
		for _, txt := range lookupTXT(ctx, sel+"._domainkey."+domain) {
			if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "k=rsa") || strings.Contains(txt, "p=") {
				dkim = append(dkim, sel)
				break
			}
		}
	}
	res["dkim_selectors"] = dkim
	res["dkim_found"] = len(dkim) > 0

	// BIMI.
	bimi := firstTXT(ctx, "default._bimi."+domain, "v=BIMI1")
	res["bimi"] = bimi != ""

	// MTA-STS + TLS-RPT.
	mtaSTS := firstTXT(ctx, "_mta-sts."+domain, "v=STSv1") != ""
	res["mta_sts"] = mtaSTS
	tlsRPT := firstTXT(ctx, "_smtp._tls."+domain, "v=TLSRPTv1") != ""
	res["tls_rpt"] = tlsRPT
	if !mtaSTS {
		findings = append(findings, fnd("No MTA-STS", "low", "MTA-STS not published — opportunistic TLS only for inbound mail."))
	}

	// DNSSEC.
	dnssec := hasDNSKEY(ctx, domain)
	res["dnssec"] = dnssec
	if !dnssec {
		findings = append(findings, fnd("DNSSEC not enabled", "low", "Zone is not signed (DNSSEC) — DNS responses are not cryptographically verifiable."))
	}

	// CAA.
	caa := lookupCAA(ctx, domain)
	res["caa"] = caa
	if len(caa) == 0 {
		findings = append(findings, fnd("No CAA records", "low", "No CAA records — any CA may issue certificates for this domain."))
	}

	res["findings"] = findings
	overall := "info"
	for _, f := range findings {
		if f["severity"] == "high" {
			overall = "high"
		} else if overall == "info" && f["severity"] == "medium" {
			overall = "medium"
		}
	}
	res["overall_severity"] = overall
	return res, nil
}

func firstTXT(ctx context.Context, name, prefix string) string {
	for _, txt := range lookupTXT(ctx, name) {
		if strings.Contains(txt, prefix) {
			return txt
		}
	}
	return ""
}

func fnd(name, sev, desc string) map[string]any {
	return map[string]any{"name": name, "severity": sev, "description": desc}
}
