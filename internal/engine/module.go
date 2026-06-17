// Package engine is the scan orchestration core for Obscura Scan.
//
// It defines the Module interface that every recon/analysis module must
// implement, a concurrency-safe SharedState for inter-module data exchange,
// and a global registry that modules populate via init().
package engine

import (
	"context"
	"fmt"
	"sync"

	"obscurascan/internal/config"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// ---------------------------------------------------------------------------
// Module result
// ---------------------------------------------------------------------------

// ModuleResult is the standardized output for all modules.
type ModuleResult struct {
	ModuleName    string         `json:"module_name"`
	Status        string         `json:"status"` // success | error | skipped
	Data          map[string]any `json:"data"`
	Error         string         `json:"error,omitempty"`
	ExecutionTime float64        `json:"execution_time"` // seconds
}

// ---------------------------------------------------------------------------
// Module interface
// ---------------------------------------------------------------------------

// Module is the unified interface for all recon/analysis modules.
type Module interface {
	// Name returns the unique identifier, e.g. "virustotal".
	Name() string
	// Description returns a human-readable summary.
	Description() string
	// Category classifies the module: recon | passive | semi-offensive | intel | analysis.
	Category() string
	// Dependencies returns the names of modules that must finish first.
	Dependencies() []string
	// RequiredKey returns the config field name whose absence causes a skip,
	// or "" for modules that need no API key (graceful degradation).
	RequiredKey() string
	// RateLimitRPM returns the max requests-per-minute for this module.
	// 0 means unlimited.
	RateLimitRPM() int
	// Run executes the module. It receives the validated target, shared
	// dependency state, global config, and the SSRF-guarded HTTP client.
	// It returns structured data or an error.
	Run(ctx context.Context, target safety.Target, deps *SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error)
}

// ---------------------------------------------------------------------------
// SharedState — concurrency-safe inter-module data store
// ---------------------------------------------------------------------------

// SharedState holds results from completed modules so that downstream
// dependents can read them. All access is guarded by a sync.RWMutex.
type SharedState struct {
	mu   sync.RWMutex
	data map[string]map[string]any
}

// NewSharedState creates an empty SharedState.
func NewSharedState() *SharedState {
	return &SharedState{data: make(map[string]map[string]any)}
}

// Get retrieves the result data for a completed module by name.
func (s *SharedState) Get(name string) (map[string]any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data[name]
	return d, ok
}

// Set stores result data for a module. It is called by the engine after a
// module finishes successfully.
func (s *SharedState) Set(name string, data map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[name] = data
}

// ---------------------------------------------------------------------------
// Global module registry
// ---------------------------------------------------------------------------

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Module)
)

// Register adds a module to the global registry. It is intended to be called
// from init() functions in module packages. Duplicate names cause a panic at
// startup (a programming error that must be caught early).
func Register(m Module) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := m.Name()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("engine: duplicate module registration: %q", name))
	}
	registry[name] = m
}

// Lookup returns the module registered under the given name.
func Lookup(name string) (Module, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	m, ok := registry[name]
	return m, ok
}

// All returns a snapshot of all registered modules keyed by name.
func All() map[string]Module {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make(map[string]Module, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}

// Names returns a sorted-stable list of all registered module names.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
