// Package notify sends scan alerts to Slack, Discord, Microsoft Teams, and
// Telegram via their webhook/bot APIs (ports the send_*_notification helpers
// from aegis.py). All channels are optional and degrade silently when unset;
// alerts fire only when a scan's risk score meets the configured threshold.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
)

// Notifier dispatches alerts to all configured channels.
type Notifier struct {
	cfg    *config.ObscuraConfig
	client *httpx.Client
}

// New builds a Notifier.
func New(cfg *config.ObscuraConfig, client *httpx.Client) *Notifier {
	return &Notifier{cfg: cfg, client: client}
}

// Summary is the minimal scan summary an alert needs.
type Summary struct {
	URL       string
	RiskScore int
	RiskLevel string
	Findings  int
	ScanID    int64
}

// NotifyScanComplete sends an alert to every configured channel when the risk
// score meets AlertThreshold. It returns the number of channels notified.
func (n *Notifier) NotifyScanComplete(ctx context.Context, s Summary) int {
	if s.RiskScore < n.cfg.AlertThreshold {
		return 0
	}
	msg := fmt.Sprintf("Obscura Scan alert (%s) for %s — risk %d/100, %d findings.",
		s.RiskLevel, s.URL, s.RiskScore, s.Findings)

	sent := 0
	if n.cfg.SlackWebhook != "" {
		if n.sendSlack(ctx, s, msg) {
			sent++
		}
	}
	if n.cfg.DiscordWebhook != "" {
		if n.post(ctx, n.cfg.DiscordWebhook, map[string]any{"content": msg}) {
			sent++
		}
	}
	if n.cfg.TeamsWebhook != "" {
		if n.post(ctx, n.cfg.TeamsWebhook, teamsCard(msg)) {
			sent++
		}
	}
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
		if n.sendTelegram(ctx, msg) {
			sent++
		}
	}
	if sent > 0 {
		slog.Info("alert dispatched", "channels", sent, "url", s.URL, "risk", s.RiskScore)
	}
	return sent
}

// NotifyChanges sends a change alert (new findings since the last scan) to all
// configured channels, regardless of the risk threshold — this is the
// continuous-monitoring signal. Returns the number of channels notified.
func (n *Notifier) NotifyChanges(ctx context.Context, url string, newFindings []string) int {
	if len(newFindings) == 0 {
		return 0
	}
	preview := newFindings
	if len(preview) > 8 {
		preview = preview[:8]
	}
	msg := fmt.Sprintf("Obscura Scan: %d new finding(s) on %s since the last scan:\n• %s",
		len(newFindings), url, strings.Join(preview, "\n• "))

	sent := 0
	if n.cfg.SlackWebhook != "" && n.post(ctx, n.cfg.SlackWebhook, map[string]any{"text": msg}) {
		sent++
	}
	if n.cfg.DiscordWebhook != "" && n.post(ctx, n.cfg.DiscordWebhook, map[string]any{"content": msg}) {
		sent++
	}
	if n.cfg.TeamsWebhook != "" && n.post(ctx, n.cfg.TeamsWebhook, teamsCard(msg)) {
		sent++
	}
	if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" && n.sendTelegram(ctx, msg) {
		sent++
	}
	if sent > 0 {
		slog.Info("change alert dispatched", "channels", sent, "url", url, "new", len(newFindings))
	}
	return sent
}

func (n *Notifier) sendSlack(ctx context.Context, s Summary, msg string) bool {
	color := "#f59e0b"
	if s.RiskLevel == "high" || s.RiskLevel == "critical" {
		color = "#dc2626"
	}
	payload := map[string]any{
		"text": msg,
		"attachments": []map[string]any{{
			"color": color,
			"fields": []map[string]any{
				{"title": "Risk Score", "value": fmt.Sprint(s.RiskScore), "short": true},
				{"title": "Risk Level", "value": s.RiskLevel, "short": true},
				{"title": "Findings", "value": fmt.Sprint(s.Findings), "short": true},
			},
		}},
	}
	return n.post(ctx, n.cfg.SlackWebhook, payload)
}

func teamsCard(msg string) map[string]any {
	return map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    "Obscura Scan Alert",
		"themeColor": "FF0000",
		"title":      "Obscura Scan Security Alert",
		"text":       msg,
	}
}

func (n *Notifier) sendTelegram(ctx context.Context, msg string) bool {
	url := "https://api.telegram.org/bot" + n.cfg.TelegramBotToken + "/sendMessage"
	return n.post(ctx, url, map[string]any{
		"chat_id": n.cfg.TelegramChatID, "text": msg, "parse_mode": "HTML",
	})
}

// post sends a JSON payload to a webhook URL through the shared (SSRF-guarded)
// client, returning whether it succeeded.
func (n *Notifier) post(ctx context.Context, url string, payload any) bool {
	b, _ := json.Marshal(payload)
	resp, err := n.client.Do(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		slog.Warn("notification failed", "url", redact(url), "err", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 400
}

// redact hides the secret tail of webhook/bot URLs in logs.
func redact(url string) string {
	if len(url) > 40 {
		return url[:30] + "…"
	}
	return url
}
