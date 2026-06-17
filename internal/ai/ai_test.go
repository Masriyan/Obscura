package ai

import (
	"context"
	"strings"
	"testing"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
)

func newTestEngine() *Engine {
	cfg := &config.ObscuraConfig{AIEnabled: true, AIPrimary: "gemini"}
	return New(cfg, httpx.New(httpx.Options{}))
}

func TestRuleBasedAnalysisFallback(t *testing.T) {
	e := newTestEngine() // no provider keys -> rule-based
	results := map[string]any{"_summary": map[string]any{"risk_score": float64(82), "risk_level": "high"}}
	out := e.AnalyzeScan(context.Background(), results, "https://example.com")
	if out["provider"] != "rule-based" {
		t.Fatalf("provider = %v, want rule-based", out["provider"])
	}
	if out["ai_available"] != false {
		t.Fatalf("ai_available = %v, want false", out["ai_available"])
	}
	if es, _ := out["executive_summary"].(string); !strings.Contains(es, "High-risk") {
		t.Fatalf("executive_summary missing High-risk narrative: %q", es)
	}
}

func TestChatFallbackNeverErrors(t *testing.T) {
	e := newTestEngine()
	out := e.Chat(context.Background(), []Message{{Role: "user", Content: "what is risky?"}}, nil)
	if out["provider"] != "rule-based" {
		t.Fatalf("provider = %v, want rule-based", out["provider"])
	}
	if r, _ := out["response"].(string); r == "" {
		t.Fatal("chat fallback must return a non-empty response")
	}
}

func TestKeywordModuleMatch(t *testing.T) {
	out := keywordModuleMatch("scan example.com for ssl and subdomain issues")
	mods, _ := out["modules"].([]string)
	if !contains(mods, "ssl_chain") || !contains(mods, "subdomain_scan") {
		t.Fatalf("keyword match modules = %v, want ssl_chain + subdomain_scan", mods)
	}
	if out["mode"] != "defensive" {
		t.Fatalf("mode = %v, want defensive", out["mode"])
	}
	// Offensive intent flips the mode.
	if got := keywordModuleMatch("run an active pentest")["mode"]; got != "semi-offensive" {
		t.Fatalf("offensive mode = %v, want semi-offensive", got)
	}
}

func TestProviderOrderHonorsPrimary(t *testing.T) {
	cfg := &config.ObscuraConfig{AIEnabled: true, AIPrimary: "anthropic"}
	e := New(cfg, httpx.New(httpx.Options{}))
	if e.providers[0].Name() != "anthropic" {
		t.Fatalf("primary provider = %s, want anthropic", e.providers[0].Name())
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
