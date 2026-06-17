// Package config implements Obscura Scan's centralized configuration.
//
// It is a faithful port of the Python core/config.py (AegisConfig), improved
// with: alias resolution (multiple accepted env spellings per logical key),
// type-safe accessors, validation warnings (never fatal), and secret masking.
//
// Load order (real OS env always wins, per godotenv semantics):
//  1. OS environment variables (highest priority, never overwritten)
//  2. .env in the current working directory
//  3. .env next to the binary (os.Executable() dir) as a fallback
//
// App-level vars use the new OBSCURA_ prefix as primary with the legacy
// FLASK_/AEGIS_ names kept as aliases. Third-party API key env vars are
// UNCHANGED (users already have them set).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

// Version is the Obscura Scan release line, mirroring AEGIS v9.0.0.
const Version = "9.0.0"

// ObscuraConfig is the type-safe configuration for the Obscura Scan platform.
type ObscuraConfig struct {
	// --- Application ---
	Version   string
	Debug     bool
	SecretKey string
	Host      string
	Port      int
	DBPath    string
	CacheTTL  int

	// --- Safety ---
	AllowInternal bool // OBSCURA_ALLOW_INTERNAL — permit scanning private/loopback targets

	// --- AI providers ---
	AIEnabled      bool
	AIPrimary      string
	GeminiKey      string
	GeminiModel    string
	OpenAIKey      string
	OpenAIModel    string
	AnthropicKey   string
	AnthropicModel string

	// --- Core intel API keys ---
	VTKey             string
	OTXKey            string
	GitHubToken       string
	ShodanKey         string
	GreyNoiseKey      string
	AbuseIPDBKey      string
	URLScanKey        string
	SecurityTrailsKey string
	HIBPKey           string

	// --- Extended OSINT ---
	HunterKey     string
	CensysID      string
	CensysSecret  string
	LeakCheckKey  string
	FOFAEmail     string
	FOFAKey       string
	DehashedEmail string
	DehashedKey   string
	FullHuntKey   string
	ZoomEyeKey    string
	BinaryEdgeKey string
	IntelXKey     string
	BuiltWithKey  string
	WhoisXMLKey   string

	// --- Notifications ---
	SlackWebhook     string
	DiscordWebhook   string
	TeamsWebhook     string
	TelegramBotToken string
	TelegramChatID   string

	// --- SIEM ---
	SplunkHECURL   string
	SplunkHECToken string
	ElasticURL     string
	ElasticAPIKey  string

	// --- Thresholds / automation ---
	DefaultTimeout      int
	AlertThreshold      int
	AutoTicketThreshold int
	MaxConcurrentScans  int
	WorkflowMaxSteps    int
	APIRateLimit        int

	// --- Enterprise ---
	APIAuthEnabled      bool
	APIRateLimitEnabled bool
	AuditLogEnabled     bool
}

// aliasTable is the single auditable definition of accepted env spellings per
// logical key. The first non-empty value wins.
var aliasTable = map[string][]string{
	// App-level (OBSCURA_ primary, legacy aliases for backward compatibility)
	"DEBUG":          {"OBSCURA_DEBUG", "FLASK_DEBUG"},
	"SECRET_KEY":     {"OBSCURA_SECRET_KEY", "FLASK_SECRET_KEY"},
	"HOST":           {"OBSCURA_HOST", "FLASK_HOST"},
	"PORT":           {"OBSCURA_PORT", "FLASK_PORT"},
	"DB_PATH":        {"OBSCURA_DB_PATH", "AEGIS_DB_PATH"},
	"CACHE_TTL":      {"OBSCURA_CACHE_TTL", "AEGIS_CACHE_TTL"},
	"ALLOW_INTERNAL": {"OBSCURA_ALLOW_INTERNAL"},

	// AI providers (multiple spellings supported)
	"GEMINI":    {"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"},
	"OPENAI":    {"OPENAI_API_KEY", "OPENAI_KEY"},
	"ANTHROPIC": {"ANTHROPIC_API_KEY", "CLAUDE_API_KEY"},

	// Core intel
	"VT":     {"VT_API_KEY", "VIRUSTOTAL_API_KEY", "VTOTAL_KEY"},
	"SHODAN": {"SHODAN_API_KEY", "SHODAN_KEY"},
	"GITHUB": {"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_API_KEY"},
}

// getenvAny returns the first non-empty, trimmed value among the given env keys.
func getenvAny(aliases ...string) string {
	for _, a := range aliases {
		if v := strings.TrimSpace(os.Getenv(a)); v != "" {
			return v
		}
	}
	return ""
}

// alias resolves a logical key through the alias table.
func alias(logical string) string {
	return getenvAny(aliasTable[logical]...)
}

func getenvDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func boolEnv(val, def string) bool {
	v := val
	if v == "" {
		v = def
	}
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "true" || v == "1" || v == "yes" || v == "on"
}

// loadDotenv loads .env files without overriding already-set OS env vars.
func loadDotenv() {
	// 1. .env in the current working dir.
	if _, err := os.Stat(".env"); err == nil {
		_ = godotenv.Load(".env")
	}
	// 2. .env next to the binary as a fallback.
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), ".env")
		if _, err := os.Stat(p); err == nil {
			_ = godotenv.Load(p)
		}
	}
}

// Load resolves env + aliases, applies defaults, and runs Validate (logging
// warnings). It never returns a fatal error for missing optional keys.
func Load() (*ObscuraConfig, error) {
	loadDotenv()

	c := &ObscuraConfig{
		Version:   Version,
		Debug:     boolEnv(alias("DEBUG"), "0"),
		SecretKey: alias("SECRET_KEY"),
		Host:      orDefault(alias("HOST"), "127.0.0.1"),
		Port:      atoiDefault(alias("PORT"), 8080),
		DBPath:    orDefault(alias("DB_PATH"), "obscura.db"),
		CacheTTL:  atoiDefault(alias("CACHE_TTL"), 3600),

		AllowInternal: boolEnv(alias("ALLOW_INTERNAL"), "false"),

		AIEnabled:      boolEnv(os.Getenv("AI_ENABLED"), "true"),
		AIPrimary:      getenvDefault("AI_PRIMARY_PROVIDER", "gemini"),
		GeminiKey:      alias("GEMINI"),
		GeminiModel:    getenvDefault("GEMINI_MODEL", "gemini-2.5-flash"),
		OpenAIKey:      alias("OPENAI"),
		OpenAIModel:    getenvDefault("OPENAI_MODEL", "gpt-4-turbo-preview"),
		AnthropicKey:   alias("ANTHROPIC"),
		AnthropicModel: getenvDefault("ANTHROPIC_MODEL", "claude-3-sonnet-20240229"),

		VTKey:             alias("VT"),
		OTXKey:            getenvAny("OTX_API_KEY"),
		GitHubToken:       alias("GITHUB"),
		ShodanKey:         alias("SHODAN"),
		GreyNoiseKey:      getenvAny("GREYNOISE_API_KEY"),
		AbuseIPDBKey:      getenvAny("ABUSEIPDB_API_KEY"),
		URLScanKey:        getenvAny("URLSCAN_API_KEY"),
		SecurityTrailsKey: getenvAny("SECURITYTRAILS_API_KEY"),
		HIBPKey:           getenvAny("HIBP_API_KEY"),

		HunterKey:     getenvAny("HUNTER_API_KEY"),
		CensysID:      getenvAny("CENSYS_API_ID"),
		CensysSecret:  getenvAny("CENSYS_API_SECRET"),
		LeakCheckKey:  getenvAny("LEAKCHECK_API_KEY"),
		FOFAEmail:     getenvAny("FOFA_EMAIL"),
		FOFAKey:       getenvAny("FOFA_API_KEY", "FOFA_KEY"),
		DehashedEmail: getenvAny("DEHASHED_EMAIL"),
		DehashedKey:   getenvAny("DEHASHED_API_KEY"),
		FullHuntKey:   getenvAny("FULLHUNT_API_KEY"),
		ZoomEyeKey:    getenvAny("ZOOMEYE_API_KEY"),
		BinaryEdgeKey: getenvAny("BINARYEDGE_API_KEY"),
		IntelXKey:     getenvAny("INTELX_API_KEY"),
		BuiltWithKey:  getenvAny("BUILTWITH_API_KEY"),
		WhoisXMLKey:   getenvAny("WHOISXML_API_KEY"),

		SlackWebhook:     getenvAny("SLACK_WEBHOOK_URL"),
		DiscordWebhook:   getenvAny("DISCORD_WEBHOOK_URL"),
		TeamsWebhook:     getenvAny("TEAMS_WEBHOOK_URL"),
		TelegramBotToken: getenvAny("TELEGRAM_BOT_TOKEN"),
		TelegramChatID:   getenvAny("TELEGRAM_CHAT_ID"),

		SplunkHECURL:   getenvAny("SPLUNK_HEC_URL"),
		SplunkHECToken: getenvAny("SPLUNK_HEC_TOKEN"),
		ElasticURL:     getenvAny("ELASTIC_URL"),
		ElasticAPIKey:  getenvAny("ELASTIC_API_KEY"),

		DefaultTimeout:      atoiDefault(os.Getenv("DEFAULT_TIMEOUT"), 15),
		AlertThreshold:      atoiDefault(os.Getenv("ALERT_THRESHOLD"), 60),
		AutoTicketThreshold: atoiDefault(os.Getenv("AUTO_TICKET_THRESHOLD"), 70),
		MaxConcurrentScans:  atoiDefault(os.Getenv("MAX_CONCURRENT_SCANS"), 5),
		WorkflowMaxSteps:    atoiDefault(os.Getenv("WORKFLOW_MAX_STEPS"), 15),
		APIRateLimit:        atoiDefault(os.Getenv("API_RATE_LIMIT"), 100),

		APIAuthEnabled:      boolEnv(os.Getenv("API_AUTH_ENABLED"), "false"),
		APIRateLimitEnabled: boolEnv(os.Getenv("API_RATE_LIMIT_ENABLED"), "true"),
		AuditLogEnabled:     boolEnv(os.Getenv("AUDIT_LOG_ENABLED"), "true"),
	}

	// If no secret key is provided, generate a random 32-byte hex key.
	if c.SecretKey == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err == nil {
			c.SecretKey = hex.EncodeToString(b)
		}
	}

	for _, w := range c.Validate() {
		slog.Warn("config", "warning", w)
	}
	return c, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// Validate returns non-fatal warnings, mirroring AegisConfig.validate().
func (c *ObscuraConfig) Validate() []string {
	var w []string
	if c.GeminiKey == "" && c.OpenAIKey == "" && c.AnthropicKey == "" {
		w = append(w, "No AI provider API keys configured. AI features will use rule-based fallback.")
	}
	if c.AIPrimary == "gemini" && c.GeminiKey == "" {
		w = append(w, "Gemini is set as primary AI provider but GEMINI_API_KEY is not configured.")
	}
	if c.VTKey == "" {
		w = append(w, "VT_API_KEY not set — VirusTotal reputation scanning disabled.")
	}
	if c.ShodanKey == "" {
		w = append(w, "SHODAN_API_KEY not set — Shodan device search disabled.")
	}
	return w
}

// ConfiguredAPIKeys counts non-empty core keys (mirrors configured_api_keys).
func (c *ObscuraConfig) ConfiguredAPIKeys() int {
	keys := []string{
		c.VTKey, c.ShodanKey, c.AbuseIPDBKey, c.GreyNoiseKey,
		c.SecurityTrailsKey, c.HIBPKey, c.GitHubToken, c.OTXKey,
		c.CensysID, c.HunterKey, c.GeminiKey, c.OpenAIKey, c.AnthropicKey,
	}
	return countNonEmpty(keys)
}

// ConfiguredNotifications counts configured notification channels.
func (c *ObscuraConfig) ConfiguredNotifications() int {
	return countNonEmpty([]string{
		c.SlackWebhook, c.DiscordWebhook, c.TeamsWebhook, c.TelegramBotToken,
	})
}

func countNonEmpty(s []string) int {
	n := 0
	for _, v := range s {
		if v != "" {
			n++
		}
	}
	return n
}

// Mask hides a secret: "" -> ""; len<=8 -> bullets; else first4 + bullets + last4.
func (c *ObscuraConfig) Mask(val string) string {
	if val == "" {
		return ""
	}
	if len(val) <= 8 {
		return "••••••••"
	}
	return val[:4] + strings.Repeat("•", len(val)-8) + val[len(val)-4:]
}

// Sanitized returns a secret-masked view for the /settings UI and JSON export.
func (c *ObscuraConfig) Sanitized() map[string]any {
	return map[string]any{
		"version":                  c.Version,
		"ai_enabled":               c.AIEnabled,
		"ai_primary_provider":      c.AIPrimary,
		"gemini_model":             c.GeminiModel,
		"openai_model":             c.OpenAIModel,
		"anthropic_model":          c.AnthropicModel,
		"configured_api_keys":      c.ConfiguredAPIKeys(),
		"configured_notifications": c.ConfiguredNotifications(),
		"max_concurrent_scans":     c.MaxConcurrentScans,
		"rate_limit":               c.APIRateLimit,
		"allow_internal":           c.AllowInternal,
	}
}

// APIKey resolves a module's RequiredKey (a logical or env-var name like
// "VT_API_KEY") to its configured value, or "" if unset. Used by the engine for
// graceful degradation: an empty result means the module is skipped, not failed.
func (c *ObscuraConfig) APIKey(name string) string {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "":
		return ""
	case "VT_API_KEY", "VIRUSTOTAL_API_KEY", "VT":
		return c.VTKey
	case "OTX_API_KEY", "OTX":
		return c.OTXKey
	case "GITHUB_TOKEN", "GITHUB":
		return c.GitHubToken
	case "SHODAN_API_KEY", "SHODAN":
		return c.ShodanKey
	case "GREYNOISE_API_KEY":
		return c.GreyNoiseKey
	case "ABUSEIPDB_API_KEY":
		return c.AbuseIPDBKey
	case "URLSCAN_API_KEY":
		return c.URLScanKey
	case "SECURITYTRAILS_API_KEY":
		return c.SecurityTrailsKey
	case "HIBP_API_KEY":
		return c.HIBPKey
	case "HUNTER_API_KEY":
		return c.HunterKey
	case "CENSYS_API_ID":
		return c.CensysID
	case "CENSYS_API_SECRET":
		return c.CensysSecret
	case "LEAKCHECK_API_KEY":
		return c.LeakCheckKey
	case "FOFA_API_KEY", "FOFA_KEY":
		return c.FOFAKey
	case "DEHASHED_API_KEY":
		return c.DehashedKey
	case "FULLHUNT_API_KEY":
		return c.FullHuntKey
	case "ZOOMEYE_API_KEY":
		return c.ZoomEyeKey
	case "BINARYEDGE_API_KEY":
		return c.BinaryEdgeKey
	case "INTELX_API_KEY":
		return c.IntelXKey
	case "BUILTWITH_API_KEY":
		return c.BuiltWithKey
	case "WHOISXML_API_KEY":
		return c.WhoisXMLKey
	case "GEMINI_API_KEY":
		return c.GeminiKey
	case "OPENAI_API_KEY":
		return c.OpenAIKey
	case "ANTHROPIC_API_KEY":
		return c.AnthropicKey
	default:
		return ""
	}
}

// Singleton accessor equivalent to lru_cache get_config().
var (
	once     sync.Once
	instance *ObscuraConfig
)

// Get returns the process-wide configuration singleton.
func Get() *ObscuraConfig {
	once.Do(func() {
		instance, _ = Load()
	})
	return instance
}
