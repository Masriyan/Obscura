package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter is a per-IP token-bucket rate limiter with idle cleanup.
type ipLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientBucket
	rps     rate.Limit
	burst   int
}

type clientBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newIPLimiter(perMinute int) *ipLimiter {
	if perMinute <= 0 {
		perMinute = 100
	}
	l := &ipLimiter{
		clients: make(map[string]*clientBucket),
		rps:     rate.Limit(float64(perMinute) / 60.0),
		burst:   perMinute,
	}
	go l.cleanupLoop()
	return l
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	c, ok := l.clients[ip]
	if !ok {
		c = &clientBucket{lim: rate.NewLimiter(l.rps, l.burst)}
		l.clients[ip] = c
	}
	c.seen = time.Now()
	l.mu.Unlock()
	return c.lim.Allow()
}

func (l *ipLimiter) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	for range t.C {
		l.mu.Lock()
		for ip, c := range l.clients {
			if time.Since(c.seen) > 10*time.Minute {
				delete(l.clients, ip)
			}
		}
		l.mu.Unlock()
	}
}

// hashKey returns the sha256 hex of an API key (what we store/compare).
func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// apiMiddleware enforces (optionally) per-IP rate limiting, Bearer-token auth,
// and audit logging on the /api/v1/* surface. Each control is toggled by config
// (APIRateLimitEnabled / APIAuthEnabled / AuditLogEnabled), so the API works
// fully open by default and hardens when enabled.
func (s *Server) apiMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		if s.cfg.APIRateLimitEnabled && s.limiter != nil && !s.limiter.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
			return
		}

		user := "anonymous"
		if s.cfg.APIAuthEnabled {
			tok := bearerToken(r)
			if tok == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
				return
			}
			name, _, ok := s.store.APIKeys().Lookup(hashKey(tok))
			if !ok {
				if s.cfg.AuditLogEnabled {
					s.store.Audit().Log("unknown", "auth_failed", r.URL.Path, ip)
				}
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid api key"})
				return
			}
			user = name
		}

		if s.cfg.AuditLogEnabled {
			s.store.Audit().Log(user, r.Method, r.URL.Path, ip)
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	// Allow X-API-Key as an alternative.
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}
