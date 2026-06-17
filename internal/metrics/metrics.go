// Package metrics is a tiny, dependency-free Prometheus text-exposition layer.
// It tracks the handful of series Obscura Scan cares about (scans, module
// outcomes, active scans, HTTP responses, scan durations) and renders them at
// /metrics. Avoiding the official client keeps the single-binary lean.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

var (
	scansTotal    atomic.Int64
	activeScans   atomic.Int64
	moduleStatus  = newCounterVec()
	httpResponses = newCounterVec()

	durMu    sync.Mutex
	durSum   float64
	durCount int64
)

// counterVec is a labeled counter (single label value used as the map key).
type counterVec struct {
	mu sync.Mutex
	v  map[string]int64
}

func newCounterVec() *counterVec { return &counterVec{v: map[string]int64{}} }

func (c *counterVec) inc(label string) {
	c.mu.Lock()
	c.v[label]++
	c.mu.Unlock()
}

func (c *counterVec) snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.v))
	for k, n := range c.v {
		out[k] = n
	}
	return out
}

// ScanStarted / ScanFinished bracket a scan to maintain the active gauge.
func ScanStarted() { activeScans.Add(1) }
func ScanFinished(durationSeconds float64) {
	activeScans.Add(-1)
	scansTotal.Add(1)
	durMu.Lock()
	durSum += durationSeconds
	durCount++
	durMu.Unlock()
}

// ModuleResult records one module outcome (success|error|skipped).
func ModuleResult(status string) { moduleStatus.inc(status) }

// HTTPResponse records an HTTP response by status-code class (2xx/3xx/4xx/5xx).
func HTTPResponse(code int) { httpResponses.inc(codeClass(code)) }

func codeClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// Handler renders the metrics in Prometheus text exposition format.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		writeCounter(w, "obscura_scans_total", "Total scans completed.", scansTotal.Load())
		writeGauge(w, "obscura_active_scans", "Scans currently running.", activeScans.Load())

		fmt.Fprintln(w, "# HELP obscura_module_results_total Module outcomes by status.")
		fmt.Fprintln(w, "# TYPE obscura_module_results_total counter")
		for _, st := range sortedKeys(moduleStatus.snapshot()) {
			fmt.Fprintf(w, "obscura_module_results_total{status=%q} %d\n", st, moduleStatus.snapshot()[st])
		}

		fmt.Fprintln(w, "# HELP obscura_http_responses_total HTTP responses by class.")
		fmt.Fprintln(w, "# TYPE obscura_http_responses_total counter")
		hr := httpResponses.snapshot()
		for _, cls := range sortedKeys(hr) {
			fmt.Fprintf(w, "obscura_http_responses_total{class=%q} %d\n", cls, hr[cls])
		}

		durMu.Lock()
		sum, count := durSum, durCount
		durMu.Unlock()
		fmt.Fprintln(w, "# HELP obscura_scan_duration_seconds Aggregate scan durations.")
		fmt.Fprintln(w, "# TYPE obscura_scan_duration_seconds summary")
		fmt.Fprintf(w, "obscura_scan_duration_seconds_sum %g\n", sum)
		fmt.Fprintf(w, "obscura_scan_duration_seconds_count %d\n", count)
	}
}

func writeCounter(w http.ResponseWriter, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}
func writeGauge(w http.ResponseWriter, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
