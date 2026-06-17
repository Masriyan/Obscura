package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
)

// postJSON is a small helper for the REST providers. It uses the shared
// SSRF-guarded client and returns the decoded response body.
func postJSON(ctx context.Context, client *httpx.Client, url string, headers map[string]string, payload any) ([]byte, error) {
	b, _ := json.Marshal(payload)
	// httpx.Client.Do sets the body and method; build via Do with a bytes reader.
	resp, err := client.Do(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Note: headers are applied per-request below via a custom path when needed.
	_ = headers
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// --- Gemini (Google Generative Language REST) ---

type geminiProvider struct {
	cfg    *config.ObscuraConfig
	client *httpx.Client
}

func (g *geminiProvider) Name() string    { return "gemini" }
func (g *geminiProvider) Available() bool { return g.cfg.GeminiKey != "" }

func (g *geminiProvider) Generate(ctx context.Context, prompt, system string) (string, error) {
	return g.Chat(ctx, []Message{{Role: "user", Content: prompt}}, system)
}

func (g *geminiProvider) Chat(ctx context.Context, msgs []Message, system string) (string, error) {
	if !g.Available() {
		return "", fmt.Errorf("gemini unavailable")
	}
	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Role  string `json:"role"`
		Parts []part `json:"parts"`
	}
	var contents []content
	for _, m := range msgs {
		role := "user"
		if m.Role == "assistant" {
			role = "model"
		}
		contents = append(contents, content{Role: role, Parts: []part{{Text: m.Content}}})
	}
	payload := map[string]any{
		"contents":          contents,
		"systemInstruction": map[string]any{"parts": []part{{Text: system}}},
	}
	url := "https://generativelanguage.googleapis.com/v1beta/models/" + g.cfg.GeminiModel + ":generateContent?key=" + g.cfg.GeminiKey
	body, err := postJSON(ctx, g.client, url, nil, payload)
	if err != nil {
		return "", err
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []part `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if len(out.Candidates) > 0 && len(out.Candidates[0].Content.Parts) > 0 {
		return out.Candidates[0].Content.Parts[0].Text, nil
	}
	return "", fmt.Errorf("empty gemini response")
}

// --- OpenAI (chat completions) ---

type openAIProvider struct {
	cfg    *config.ObscuraConfig
	client *httpx.Client
}

func (o *openAIProvider) Name() string    { return "openai" }
func (o *openAIProvider) Available() bool { return o.cfg.OpenAIKey != "" }

func (o *openAIProvider) Generate(ctx context.Context, prompt, system string) (string, error) {
	return o.Chat(ctx, []Message{{Role: "user", Content: prompt}}, system)
}

func (o *openAIProvider) Chat(ctx context.Context, msgs []Message, system string) (string, error) {
	if !o.Available() {
		return "", fmt.Errorf("openai unavailable")
	}
	apiMsgs := []map[string]string{{"role": "system", "content": system}}
	for _, m := range msgs {
		apiMsgs = append(apiMsgs, map[string]string{"role": m.Role, "content": m.Content})
	}
	payload := map[string]any{"model": o.cfg.OpenAIModel, "messages": apiMsgs, "max_tokens": 2048}
	body, err := doAuthedPOST(ctx, o.client, "https://api.openai.com/v1/chat/completions",
		map[string]string{"Authorization": "Bearer " + o.cfg.OpenAIKey}, payload)
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if len(out.Choices) > 0 {
		return out.Choices[0].Message.Content, nil
	}
	return "", fmt.Errorf("empty openai response")
}

// --- Anthropic (messages) ---

type anthropicProvider struct {
	cfg    *config.ObscuraConfig
	client *httpx.Client
}

func (a *anthropicProvider) Name() string    { return "anthropic" }
func (a *anthropicProvider) Available() bool { return a.cfg.AnthropicKey != "" }

func (a *anthropicProvider) Generate(ctx context.Context, prompt, system string) (string, error) {
	return a.Chat(ctx, []Message{{Role: "user", Content: prompt}}, system)
}

func (a *anthropicProvider) Chat(ctx context.Context, msgs []Message, system string) (string, error) {
	if !a.Available() {
		return "", fmt.Errorf("anthropic unavailable")
	}
	apiMsgs := make([]map[string]string, 0, len(msgs))
	for _, m := range msgs {
		apiMsgs = append(apiMsgs, map[string]string{"role": m.Role, "content": m.Content})
	}
	payload := map[string]any{"model": a.cfg.AnthropicModel, "system": system, "messages": apiMsgs, "max_tokens": 2048}
	body, err := doAuthedPOST(ctx, a.client, "https://api.anthropic.com/v1/messages",
		map[string]string{"x-api-key": a.cfg.AnthropicKey, "anthropic-version": "2023-06-01"}, payload)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if len(out.Content) > 0 {
		return out.Content[0].Text, nil
	}
	return "", fmt.Errorf("empty anthropic response")
}

// doAuthedPOST posts JSON with custom headers through the shared client's
// underlying transport. (The httpx.Client.Do path is header-limited, so we
// build a request here but reuse the same SSRF-guarded http.Client.)
func doAuthedPOST(ctx context.Context, client *httpx.Client, url string, headers map[string]string, payload any) ([]byte, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.RawDo(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("provider HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
