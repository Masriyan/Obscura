package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"obscurascan/internal/metrics"
)

type ctxKey string

const csrfCtxKey ctxKey = "csrf"

const csrfCookie = "obx_csrf"

// csrfMiddleware implements double-submit-cookie CSRF protection for browser
// form POSTs. The /api/v1/* surface is exempt (token-auth'd, not cookie/CSRF).
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(csrfCookie); err == nil {
			token = c.Value
		}
		if token == "" {
			token = randToken()
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookie,
				Value:    token,
				Path:     "/",
				HttpOnly: false, // readable so JS/htmx can echo it if needed
				SameSite: http.SameSiteLaxMode,
			})
		}
		r = r.WithContext(context.WithValue(r.Context(), csrfCtxKey, token))

		if isUnsafe(r.Method) && !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			submitted := r.FormValue("csrf_token")
			if submitted == "" || submitted != token {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// csrfToken returns the per-request CSRF token for templates.
func csrfToken(r *http.Request) string {
	if v, ok := r.Context().Value(csrfCtxKey).(string); ok {
		return v
	}
	return ""
}

// requestLogger logs each request via slog with method, path, status, duration.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if r.URL.Path != "/metrics" {
			metrics.HTTPResponse(sw.status)
		}
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush passes through so SSE streaming still works behind the logger wrapper.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
