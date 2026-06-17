// Package httpx is the shared HTTP client for Obscura Scan modules.
//
// It ports core/utils.py fetch_with_retry: a single shared *http.Client with
// explicit timeouts, exponential backoff with jitter, bounded retries, and a
// per-host circuit breaker. The transport uses the SSRF-guarded dialer from
// internal/safety, so every module fetches through the guard and it cannot be
// bypassed per-module or via redirects.
package httpx

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	neturl "net/url"
	"sync"
	"time"

	"obscurascan/internal/safety"
)

// breakerState models a simple per-host circuit breaker (CLOSED/OPEN/HALF-OPEN).
type breakerState struct {
	failures        int
	lastFailureTime time.Time
	open            bool
}

// circuitBreaker tracks consecutive failures per host.
type circuitBreaker struct {
	mu               sync.Mutex
	hosts            map[string]*breakerState
	failureThreshold int
	recoveryTimeout  time.Duration
}

func newCircuitBreaker() *circuitBreaker {
	return &circuitBreaker{
		hosts:            make(map[string]*breakerState),
		failureThreshold: 5,
		recoveryTimeout:  60 * time.Second,
	}
}

func (cb *circuitBreaker) canExecute(host string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	st := cb.hosts[host]
	if st == nil || !st.open {
		return true
	}
	if time.Since(st.lastFailureTime) >= cb.recoveryTimeout {
		// Half-open: allow a trial request.
		return true
	}
	return false
}

func (cb *circuitBreaker) recordFailure(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	st := cb.hosts[host]
	if st == nil {
		st = &breakerState{}
		cb.hosts[host] = st
	}
	st.failures++
	st.lastFailureTime = time.Now()
	if st.failures >= cb.failureThreshold {
		st.open = true
	}
}

func (cb *circuitBreaker) recordSuccess(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if st := cb.hosts[host]; st != nil {
		st.failures = 0
		st.open = false
	}
}

// Client is the shared, SSRF-guarded HTTP client with retry + circuit breaking.
type Client struct {
	hc         *http.Client
	cb         *circuitBreaker
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	userAgent  string
}

// Options configures a Client.
type Options struct {
	AllowInternal bool
	Timeout       time.Duration // per-request timeout
	MaxRetries    int
	UserAgent     string
}

// New builds a shared Client. Timeout defaults to 15s, retries to 3.
func New(opts Options) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 3
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Obscura Scan/9.0.0 (+https://security-life.org)"
	}

	dialer := safety.NewDialer(opts.AllowInternal)
	dialer.Timeout = 10 * time.Second
	dialer.KeepAlive = 30 * time.Second

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	hc := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		// Cap redirects; each redirect re-dials, so the guard re-validates the hop.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	return &Client{
		hc:         hc,
		cb:         newCircuitBreaker(),
		maxRetries: opts.MaxRetries,
		baseDelay:  1 * time.Second,
		maxDelay:   10 * time.Second,
		userAgent:  opts.UserAgent,
	}
}

// Do performs an HTTP request with retry + circuit breaking. The caller owns
// the returned response body and must Close it.
func (c *Client) Do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	host := hostOf(url)
	if !c.cb.canExecute(host) {
		return nil, fmt.Errorf("circuit breaker open for %s", host)
	}

	delay := c.baseDelay
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				c.cb.recordFailure(host)
				return nil, ctx.Err()
			}
		} else if isRetryableStatus(resp.StatusCode) {
			resp.Body.Close()
			lastErr = fmt.Errorf("server returned %d", resp.StatusCode)
		} else {
			c.cb.recordSuccess(host)
			return resp, nil
		}

		if attempt == c.maxRetries {
			break
		}
		// Exponential backoff with full jitter.
		sleep := time.Duration(rand.Int63n(int64(delay) + 1))
		select {
		case <-ctx.Done():
			c.cb.recordFailure(host)
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
		if delay *= 2; delay > c.maxDelay {
			delay = c.maxDelay
		}
	}

	c.cb.recordFailure(host)
	return nil, fmt.Errorf("max retries reached for %s: %w", url, lastErr)
}

// Get is a convenience wrapper around Do.
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, url, nil)
}

// RawDo executes a pre-built request on the shared (SSRF-guarded) client
// without the retry/circuit-breaker wrapper. Used where custom headers are
// required (e.g. authenticated AI provider calls).
func (c *Client) RawDo(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	return c.hc.Do(req)
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func hostOf(rawurl string) string {
	if u, err := neturl.Parse(rawurl); err == nil {
		h := u.Hostname()
		if h != "" {
			return h
		}
	}
	return rawurl
}
