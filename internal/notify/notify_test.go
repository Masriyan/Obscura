package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
)

// testClient allows connecting to the httptest server (loopback) by enabling
// the internal-target override on the shared SSRF-guarded client.
func testClient() *httpx.Client {
	return httpx.New(httpx.Options{AllowInternal: true})
}

func TestNotifyBelowThresholdSkips(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()

	cfg := &config.ObscuraConfig{AlertThreshold: 60, SlackWebhook: srv.URL}
	n := New(cfg, testClient())
	sent := n.NotifyScanComplete(context.Background(), Summary{URL: "x", RiskScore: 30, RiskLevel: "medium"})
	if sent != 0 || hits != 0 {
		t.Fatalf("below-threshold alert should not fire (sent=%d hits=%d)", sent, hits)
	}
}

func TestNotifyAllChannels(t *testing.T) {
	var mu sync.Mutex
	got := map[string]map[string]any{}
	mk := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(body, &payload)
			mu.Lock()
			got[name] = payload
			mu.Unlock()
		}))
	}
	slack, discord, teams, telegram := mk("slack"), mk("discord"), mk("teams"), mk("telegram")
	defer slack.Close()
	defer discord.Close()
	defer teams.Close()
	defer telegram.Close()

	cfg := &config.ObscuraConfig{
		AlertThreshold:   50,
		SlackWebhook:     slack.URL,
		DiscordWebhook:   discord.URL,
		TeamsWebhook:     teams.URL,
		TelegramBotToken: "tok", TelegramChatID: "123",
	}
	// Point the Telegram call at our test server by overriding the host via a
	// custom token URL is not possible; instead assert the other three and that
	// the count reflects all configured channels that returned 200.
	_ = telegram

	n := New(cfg, testClient())
	sent := n.NotifyScanComplete(context.Background(), Summary{URL: "https://target", RiskScore: 82, RiskLevel: "critical", Findings: 3})

	// Slack/Discord/Teams should all have received a payload.
	if got["slack"] == nil || got["discord"] == nil || got["teams"] == nil {
		t.Fatalf("expected slack/discord/teams payloads, got %v", keys(got))
	}
	if got["discord"]["content"] == nil {
		t.Errorf("discord payload missing content")
	}
	if got["teams"]["@type"] != "MessageCard" {
		t.Errorf("teams payload not a MessageCard: %v", got["teams"]["@type"])
	}
	if got["slack"]["attachments"] == nil {
		t.Errorf("slack payload missing attachments")
	}
	// Telegram points at api.telegram.org (won't connect in test) so >=3.
	if sent < 3 {
		t.Fatalf("expected >=3 channels notified, got %d", sent)
	}
}

func keys(m map[string]map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
