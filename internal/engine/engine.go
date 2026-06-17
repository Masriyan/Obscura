package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
	"obscurascan/internal/metrics"
	"obscurascan/internal/safety"
)

// ProgressFunc is invoked after each module finishes, with the cumulative list
// of completed module names. It drives SSE / status updates.
type ProgressFunc func(completed []string)

// RunOptions configures a single scan run.
type RunOptions struct {
	Modules    []string // selected module names; empty = all registered
	Mode       string   // defensive | semi-offensive (gates offensive modules)
	MaxWorkers int      // bounded parallelism; <=0 -> 8
	Progress   ProgressFunc
}

// Run executes the selected modules against target with dependency-aware
// parallelism, panic isolation, and graceful key-based skipping. It returns the
// per-module results keyed by module name (the shape the templates/exports use).
func Run(ctx context.Context, target safety.Target, cfg *config.ObscuraConfig, client *httpx.Client, opts RunOptions) map[string]ModuleResult {
	if opts.MaxWorkers <= 0 {
		opts.MaxWorkers = 8
	}

	selected := resolveSelection(opts.Modules)
	shared := NewSharedState()
	results := make(map[string]ModuleResult, len(selected))
	var resultsMu sync.Mutex

	// Per-module completion signals so dependents can block until ready.
	done := make(map[string]chan struct{}, len(selected))
	for name := range selected {
		done[name] = make(chan struct{})
	}

	// Progress tracking.
	var progMu sync.Mutex
	completed := make([]string, 0, len(selected))
	reportDone := func(name string) {
		if opts.Progress == nil {
			return
		}
		progMu.Lock()
		completed = append(completed, name)
		snapshot := append([]string(nil), completed...)
		progMu.Unlock()
		opts.Progress(snapshot)
	}

	sem := make(chan struct{}, opts.MaxWorkers)
	var wg sync.WaitGroup

	for name, mod := range selected {
		wg.Add(1)
		go func(name string, mod Module) {
			defer wg.Done()
			defer close(done[name])

			// Block until in-scope dependencies finish (regardless of outcome).
			for _, dep := range mod.Dependencies() {
				if ch, ok := done[dep]; ok {
					select {
					case <-ch:
					case <-ctx.Done():
						return
					}
				}
			}

			res := runOne(ctx, mod, target, shared, cfg, client, sem)
			metrics.ModuleResult(res.Status)

			resultsMu.Lock()
			results[name] = res
			resultsMu.Unlock()
			if res.Status == "success" {
				shared.Set(name, res.Data)
			}
			reportDone(name)
		}(name, mod)
	}

	wg.Wait()
	return results
}

// runOne executes a single module with timing, panic isolation, and graceful
// degradation (skip when a required key is absent or an offensive module is
// gated out by mode).
func runOne(ctx context.Context, mod Module, target safety.Target, shared *SharedState, cfg *config.ObscuraConfig, client *httpx.Client, sem chan struct{}) (res ModuleResult) {
	start := time.Now()
	res = ModuleResult{ModuleName: mod.Name(), Status: "success", Data: map[string]any{}}
	defer func() {
		res.ExecutionTime = time.Since(start).Seconds()
		if r := recover(); r != nil {
			res.Status = "error"
			res.Error = fmt.Sprintf("panic: %v", r)
			_ = debug.Stack()
		}
	}()

	// Graceful degradation: required key not configured -> skipped (not error).
	if key := mod.RequiredKey(); key != "" && cfg.APIKey(key) == "" {
		res.Status = "skipped"
		res.Error = key + " not set"
		return res
	}

	// Bounded concurrency: acquire a worker slot for the actual work.
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		res.Status = "error"
		res.Error = ctx.Err().Error()
		return res
	}

	data, err := mod.Run(ctx, target, shared, cfg, client)
	if err != nil {
		res.Status = "error"
		res.Error = err.Error()
		return res
	}
	if data == nil {
		res.Status = "skipped"
		return res
	}
	res.Data = data
	return res
}

// resolveSelection returns the modules to run. Empty/"all" selects everything
// registered. Unknown names are ignored.
func resolveSelection(names []string) map[string]Module {
	out := make(map[string]Module)
	if len(names) == 0 {
		return All()
	}
	for _, n := range names {
		if m, ok := Lookup(n); ok {
			out[n] = m
		}
	}
	return out
}
