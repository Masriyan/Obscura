package config

import "testing"

func TestGetenvAnyFirstNonEmpty(t *testing.T) {
	t.Setenv("A_ONE", "")
	t.Setenv("A_TWO", "  value  ")
	t.Setenv("A_THREE", "third")
	if got := getenvAny("A_ONE", "A_TWO", "A_THREE"); got != "value" {
		t.Fatalf("getenvAny = %q, want trimmed %q", got, "value")
	}
	if got := getenvAny("NOPE_1", "NOPE_2"); got != "" {
		t.Fatalf("getenvAny on all-empty = %q, want empty", got)
	}
}

func TestAliasResolutionAndOSPriority(t *testing.T) {
	// Legacy alias resolves when the primary is unset.
	t.Setenv("FLASK_HOST", "10.0.0.1")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "10.0.0.1" {
		t.Fatalf("Host via legacy alias = %q, want 10.0.0.1", cfg.Host)
	}
	// Primary OBSCURA_ var wins over the legacy alias.
	t.Setenv("OBSCURA_HOST", "192.168.5.5")
	cfg, _ = Load()
	if cfg.Host != "192.168.5.5" {
		t.Fatalf("Host with OBSCURA_HOST set = %q, want 192.168.5.5", cfg.Host)
	}
}

func TestVTAliasSpellings(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "vt-secret")
	cfg, _ := Load()
	if cfg.VTKey != "vt-secret" {
		t.Fatalf("VTKey via VIRUSTOTAL_API_KEY = %q", cfg.VTKey)
	}
}

func TestDefaultsAndRandomSecret(t *testing.T) {
	cfg, _ := Load()
	if cfg.Port != 8080 {
		t.Fatalf("default Port = %d, want 8080", cfg.Port)
	}
	if cfg.DBPath != "obscura.db" {
		t.Fatalf("default DBPath = %q, want obscura.db", cfg.DBPath)
	}
	if cfg.CacheTTL != 3600 {
		t.Fatalf("default CacheTTL = %d, want 3600", cfg.CacheTTL)
	}
	if len(cfg.SecretKey) == 0 {
		t.Fatal("empty SecretKey should be randomly generated")
	}
}

func TestMask(t *testing.T) {
	c := &ObscuraConfig{}
	if got := c.Mask(""); got != "" {
		t.Fatalf("Mask(empty) = %q", got)
	}
	if got := c.Mask("eightchr"); got != "••••••••" {
		t.Fatalf("Mask(len8) = %q", got)
	}
	long := "sk-1234567890abcd" // len 17
	want := "sk-1" + "•••••••••" + "abcd"
	if got := c.Mask(long); got != want {
		t.Fatalf("Mask(long) = %q, want %q", got, want)
	}
}

func TestValidateWarnings(t *testing.T) {
	c := &ObscuraConfig{AIPrimary: "gemini"} // nothing configured
	w := c.Validate()
	if len(w) == 0 {
		t.Fatal("expected validation warnings for empty config")
	}
	// With all the relevant keys set, the four warnings disappear.
	full := &ObscuraConfig{
		AIPrimary: "gemini", GeminiKey: "g", VTKey: "v", ShodanKey: "s",
	}
	if w := full.Validate(); len(w) != 0 {
		t.Fatalf("expected no warnings, got %v", w)
	}
}
