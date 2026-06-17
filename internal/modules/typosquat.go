package modules

import (
	"context"
	"sort"
	"strings"
	"sync"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// typosquatModule generates look-alike domains and resolves them to find
// registered squats (name "typosquat") — dnstwist-style, pure DNS, no API.
type typosquatModule struct{}

func init() { engine.Register(typosquatModule{}) }

func (typosquatModule) Name() string { return "typosquat" }
func (typosquatModule) Description() string {
	return "Generates typo/homoglyph look-alike domains and resolves them to flag potential phishing/squatting."
}
func (typosquatModule) Category() string       { return "intel" }
func (typosquatModule) Dependencies() []string { return nil }
func (typosquatModule) RequiredKey() string    { return "" }
func (typosquatModule) RateLimitRPM() int      { return 0 }

var (
	keyboardAdj = map[rune]string{
		'a': "qwsz", 'b': "vghn", 'c': "xdfv", 'd': "serfcx", 'e': "wsdr", 'f': "drtgvc",
		'g': "ftyhbv", 'h': "gyujnb", 'i': "ujko", 'j': "huikmn", 'k': "jiolm", 'l': "kop",
		'm': "njk", 'n': "bhjm", 'o': "iklp", 'p': "ol", 'q': "wa", 'r': "edft", 's': "awedxz",
		't': "rfgy", 'u': "yhji", 'v': "cfgb", 'w': "qase", 'x': "zsdc", 'y': "tghu", 'z': "asx",
	}
	homoglyphs = map[rune]string{
		'o': "0", '0': "o", 'l': "1i", 'i': "1l", '1': "li", 'e': "3", 's': "5", 'a': "4", 'g': "9", 'b': "8", 'z': "2",
	}
	altTLDs = []string{"com", "net", "org", "co", "io", "info", "biz", "online", "site", "app", "dev", "xyz", "us", "cc"}
)

func (typosquatModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, _ *httpx.Client) (map[string]any, error) {
	domain := target.Host
	dot := strings.IndexByte(domain, '.')
	if dot < 1 {
		return map[string]any{"error": "cannot derive label from " + domain}, nil
	}
	label := domain[:dot]
	suffix := domain[dot:] // e.g. ".com"

	cands := map[string]bool{}
	addLabel := func(l string) {
		if l != "" && l != label {
			cands[l+suffix] = true
		}
	}
	rl := []rune(label)
	// Omission.
	for i := range rl {
		addLabel(string(rl[:i]) + string(rl[i+1:]))
	}
	// Repetition.
	for i := range rl {
		addLabel(string(rl[:i+1]) + string(rl[i]) + string(rl[i+1:]))
	}
	// Transposition (swap adjacent).
	for i := 0; i+1 < len(rl); i++ {
		s := append([]rune{}, rl...)
		s[i], s[i+1] = s[i+1], s[i]
		addLabel(string(s))
	}
	// Keyboard-adjacent replacement.
	for i, c := range rl {
		for _, r := range keyboardAdj[c] {
			s := append([]rune{}, rl...)
			s[i] = r
			addLabel(string(s))
		}
	}
	// Homoglyph replacement.
	for i, c := range rl {
		for _, r := range homoglyphs[c] {
			s := append([]rune{}, rl...)
			s[i] = r
			addLabel(string(s))
		}
	}
	// Hyphenation.
	for i := 1; i < len(rl); i++ {
		addLabel(string(rl[:i]) + "-" + string(rl[i:]))
	}
	// TLD swap (registrable base swapped to alternative TLDs).
	if lastDot := strings.LastIndexByte(domain, '.'); lastDot > 0 {
		base := domain[:lastDot]
		curTLD := domain[lastDot+1:]
		for _, t := range altTLDs {
			if t != curTLD {
				cands[base+"."+t] = true
			}
		}
	}

	candidates := keysOf(cands)
	sort.Strings(candidates)

	var (
		mu         sync.Mutex
		registered []map[string]any
		wg         sync.WaitGroup
		sem        = make(chan struct{}, 30)
	)
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ips := lookupA(ctx, d); len(ips) > 0 {
				mu.Lock()
				registered = append(registered, map[string]any{"domain": d, "ips": ips})
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()

	sort.Slice(registered, func(i, j int) bool { return registered[i]["domain"].(string) < registered[j]["domain"].(string) })

	findings := []map[string]any{}
	for _, r := range registered {
		findings = append(findings, map[string]any{
			"name": "Look-alike domain registered: " + r["domain"].(string), "severity": "medium",
			"description": "Resolvable typo/homoglyph variant — possible phishing or brand abuse.",
		})
	}
	overall := "info"
	if len(findings) > 0 {
		overall = "medium"
	}
	return map[string]any{
		"domain":           domain,
		"generated":        len(candidates),
		"registered":       registered,
		"registered_count": len(registered),
		"findings":         findings,
		"overall_severity": overall,
	}, nil
}
