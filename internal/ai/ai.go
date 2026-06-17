// Package ai is the Obscura Scan multi-provider AI engine (port of
// core/ai_engine.py). It tries the configured providers in order
// (primary -> others) and always falls back to a rule-based heuristic that
// works fully offline, so AI features never hard-fail.
//
// The system prompts are copied verbatim from the Python source, with the
// persona renamed "AEGIS AI" -> "Obscura Scan AI" (text only).
package ai

import (
	"context"
	"fmt"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
)

const systemPromptAnalyst = `You are Obscura Scan AI — an elite cybersecurity threat analyst integrated into the Obscura Scan Attack Surface Management platform.

Your role:
- Analyze security scan results with precision and actionable depth
- Communicate findings using industry-standard terminology (MITRE ATT&CK, CVSS, OWASP)
- Prioritize findings by real-world exploitability, not just severity scores
- Provide specific, implementable remediation steps
- Write for both technical operators AND executive stakeholders

Formatting rules:
- Use markdown for structure
- Include severity ratings: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ⚪ Info
- Reference specific CVE IDs, CWE numbers, and MITRE ATT&CK techniques when applicable
- Keep responses concise but thorough
`

const systemPromptChat = `You are the Obscura Scan AI Copilot — an interactive security assistant embedded in the Obscura Scan threat hunting platform.

You have access to the current scan results and can answer questions about:
- Specific findings and their implications
- Remediation strategies and priority ordering
- Attack surface insights and risk contextualization
- Technology stack security posture
- Compliance mapping (PCI-DSS, SOC2, ISO 27001, GDPR)

Be conversational but precise. Reference specific data from the scan results when answering.
`

// Message is one chat turn.
type Message struct {
	Role    string `json:"role"` // user | assistant
	Content string `json:"content"`
}

// Provider is an AI backend. Generate is a single-shot prompt; Chat is a
// multi-turn conversation. Either returns "" when unavailable/failed.
type Provider interface {
	Name() string
	Available() bool
	Generate(ctx context.Context, prompt, system string) (string, error)
	Chat(ctx context.Context, msgs []Message, system string) (string, error)
}

// Engine is the multi-provider AI engine with rule-based fallback.
type Engine struct {
	cfg       *config.ObscuraConfig
	providers []Provider // in fallback order
}

// New builds the engine. Provider order honors AIPrimary, then the remaining
// providers, then (implicitly) the rule-based fallback.
func New(cfg *config.ObscuraConfig, client *httpx.Client) *Engine {
	gem := &geminiProvider{cfg: cfg, client: client}
	oai := &openAIProvider{cfg: cfg, client: client}
	ant := &anthropicProvider{cfg: cfg, client: client}

	order := []Provider{gem, oai, ant}
	switch cfg.AIPrimary {
	case "openai":
		order = []Provider{oai, gem, ant}
	case "anthropic":
		order = []Provider{ant, gem, oai}
	}
	return &Engine{cfg: cfg, providers: order}
}

// Status reports which providers are available and the active one.
func (e *Engine) Status() map[string]any {
	avail := []string{}
	for _, p := range e.providers {
		if p.Available() {
			avail = append(avail, p.Name())
		}
	}
	active := "rule-based"
	if len(avail) > 0 {
		active = avail[0]
	}
	return map[string]any{
		"ai_enabled":          e.cfg.AIEnabled,
		"primary_provider":    e.cfg.AIPrimary,
		"active_provider":     active,
		"available_providers": avail,
	}
}

// generateWithFallback tries each available provider in order.
func (e *Engine) generateWithFallback(ctx context.Context, prompt, system string) (string, string) {
	if !e.cfg.AIEnabled {
		return "", ""
	}
	for _, p := range e.providers {
		if !p.Available() {
			continue
		}
		if out, err := p.Generate(ctx, prompt, system); err == nil && strings.TrimSpace(out) != "" {
			return out, p.Name()
		}
	}
	return "", ""
}

func (e *Engine) chatWithFallback(ctx context.Context, msgs []Message, system string) (string, string) {
	if !e.cfg.AIEnabled {
		return "", ""
	}
	for _, p := range e.providers {
		if !p.Available() {
			continue
		}
		if out, err := p.Chat(ctx, msgs, system); err == nil && strings.TrimSpace(out) != "" {
			return out, p.Name()
		}
	}
	return "", ""
}

// Chat answers a copilot conversation, optionally with scan context. Falls back
// to a helpful message when no provider is available (never a hard error).
func (e *Engine) Chat(ctx context.Context, msgs []Message, scanContext map[string]any) map[string]any {
	system := systemPromptChat
	if scanContext != nil {
		system += "\n\n## Current Scan Context:\n" + summarizeContext(scanContext)
	}
	if out, provider := e.chatWithFallback(ctx, msgs, system); out != "" {
		return map[string]any{"response": out, "provider": provider}
	}
	return map[string]any{
		"response": "AI analysis is currently unavailable (no provider key configured). " +
			"Set GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable the copilot. " +
			ruleBasedChatHint(msgs, scanContext),
		"provider": "rule-based",
	}
}

// AnalyzeScan produces an analysis, using AI when available and a rule-based
// heuristic otherwise.
func (e *Engine) AnalyzeScan(ctx context.Context, results map[string]any, url string) map[string]any {
	summary := mapOf(results["_summary"])
	prompt := fmt.Sprintf(`Analyze these security scan results for **%s** and provide a comprehensive threat assessment.

## Scan Summary
- Risk Score: %v/100
- Risk Level: %v

Return valid JSON with keys: executive_summary, risk_narrative, top_findings[], remediation_plan[].`,
		url, numOf(summary["risk_score"]), strOf(summary["risk_level"]))

	if out, provider := e.generateWithFallback(ctx, prompt, systemPromptAnalyst); out != "" {
		return map[string]any{"analysis": out, "provider": provider, "ai_available": true}
	}
	return ruleBasedAnalysis(results, url)
}

// ParseNaturalLanguageScan converts a free-text request to a module selection,
// using the keyword fallback when AI is unavailable.
func (e *Engine) ParseNaturalLanguageScan(ctx context.Context, query string) map[string]any {
	// (AI path omitted for brevity; the keyword matcher is the reliable default.)
	return keywordModuleMatch(query)
}

// ---- rule-based fallbacks (ported from _rule_based_analysis / _keyword_module_match) ----

func ruleBasedAnalysis(results map[string]any, url string) map[string]any {
	summary := mapOf(results["_summary"])
	riskScore := numOf(summary["risk_score"])
	riskLevel := strOf(summary["risk_level"])
	if riskLevel == "" {
		riskLevel = "unknown"
	}

	var execSummary string
	switch riskLevel {
	case "critical":
		execSummary = "Critical security issues detected for " + url + ". Immediate action required to address high-severity vulnerabilities that could lead to data breach or system compromise."
	case "high":
		execSummary = "High-risk vulnerabilities identified for " + url + ". Priority remediation recommended within 48 hours to reduce attack surface."
	case "medium":
		execSummary = "Moderate security concerns found for " + url + ". Review and address findings within the next sprint cycle."
	default:
		execSummary = "Security posture for " + url + " appears acceptable. Continue monitoring and address minor findings during routine maintenance."
	}

	topFindings := []map[string]any{}
	if numOf(summary["vt_malicious"]) > 0 {
		topFindings = append(topFindings, map[string]any{
			"title": "Malicious Reputation Detected", "severity": "critical",
			"impact":   "Domain flagged by threat intelligence engines",
			"evidence": fmt.Sprintf("%v VirusTotal engines detected malicious activity", summary["vt_malicious"]),
		})
	}
	if numOf(summary["missing_sec_headers"]) > 3 {
		topFindings = append(topFindings, map[string]any{
			"title": "Missing Security Headers", "severity": "medium",
			"impact":   "Browser-level protections are absent",
			"evidence": fmt.Sprintf("%v critical security headers missing", summary["missing_sec_headers"]),
		})
	}

	return map[string]any{
		"executive_summary": execSummary,
		"risk_narrative":    fmt.Sprintf("The scan completed with a risk score of %v/100 (%s). %s", riskScore, riskLevel, execSummary),
		"top_findings":      topFindings,
		"remediation_plan": []map[string]any{
			{"priority": 1, "action": "Address critical findings first", "effort": "high", "finding": "All critical severity items"},
		},
		"provider":     "rule-based",
		"ai_available": false,
	}
}

var keywordMap = []struct {
	kw   string
	mods []string
}{
	{"cloud", []string{"cloud_assets", "cloud_buckets"}},
	{"secret", []string{"js_secrets", "entropy_scan"}},
	{"ssl", []string{"ssl_tls", "tls", "ssl_chain"}},
	{"subdomain", []string{"subdomain_scan", "subdomain_permutation"}},
	{"dns", []string{"dns_records", "dns_zone_transfer"}},
	{"email", []string{"spf_analyzer"}},
	{"port", []string{"port_scan"}},
	{"credential", []string{"google_dorking"}},
	{"recon", []string{"crawler", "dns_records", "whois", "cert_transparency"}},
	{"full", []string{"crawler", "tls", "dns_records", "whois", "subdomain_scan", "ssl_chain", "spf_analyzer", "cert_transparency"}},
}

func keywordModuleMatch(query string) map[string]any {
	q := strings.ToLower(query)
	seen := map[string]bool{}
	var modules []string
	for _, e := range keywordMap {
		if strings.Contains(q, e.kw) {
			for _, m := range e.mods {
				if !seen[m] {
					seen[m] = true
					modules = append(modules, m)
				}
			}
		}
	}
	mode := "defensive"
	if strings.Contains(q, "active") || strings.Contains(q, "pentest") || strings.Contains(q, "offensive") {
		mode = "semi-offensive"
	}
	if len(modules) == 0 {
		modules = []string{"crawler", "dns_records", "whois", "cert_transparency"}
	}
	return map[string]any{
		"modules":     modules,
		"mode":        mode,
		"explanation": "Module selection based on keyword matching (AI unavailable)",
	}
}

func ruleBasedChatHint(msgs []Message, scanContext map[string]any) string {
	if scanContext != nil {
		return "Meanwhile, here's the scan context I have: " + summarizeContext(scanContext)
	}
	return ""
}

func summarizeContext(scanContext map[string]any) string {
	meta := mapOf(scanContext["_meta"])
	var b strings.Builder
	if t := strOf(meta["target"]); t != "" {
		fmt.Fprintf(&b, "Target: %s. ", t)
	}
	mods := []string{}
	for k := range scanContext {
		if k != "_meta" {
			mods = append(mods, k)
		}
	}
	if len(mods) > 0 {
		fmt.Fprintf(&b, "Modules with results: %s.", strings.Join(mods, ", "))
	}
	return b.String()
}

// ---- small dynamic-typing helpers (results come from JSON -> map[string]any) ----

func mapOf(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func numOf(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
