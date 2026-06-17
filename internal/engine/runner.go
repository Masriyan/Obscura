package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"obscurascan/internal/config"
	"obscurascan/internal/export"
	"obscurascan/internal/httpx"
	"obscurascan/internal/metrics"
	"obscurascan/internal/ml"
	"obscurascan/internal/notify"
	"obscurascan/internal/safety"
	"obscurascan/internal/store"
)

// Runner orchestrates persisted scan tasks: cache lookup, execution, progress
// updates, and result persistence. It ports core/scanner.py run_scan_task.
type Runner struct {
	store    *store.Store
	cfg      *config.ObscuraConfig
	client   *httpx.Client
	notifier *notify.Notifier
}

// NewRunner builds a Runner.
func NewRunner(st *store.Store, cfg *config.ObscuraConfig, client *httpx.Client) *Runner {
	return &Runner{store: st, cfg: cfg, client: client, notifier: notify.New(cfg, client)}
}

// RunTask executes a scan for an existing task row. It updates task state to
// PROGRESS, runs modules with progress callbacks, persists results to scans,
// and marks the task SUCCESS/FAILURE. The assembled results map is returned.
func (r *Runner) RunTask(ctx context.Context, taskID string, target safety.Target, opts RunOptions) (map[string]any, error) {
	metrics.ScanStarted()
	start := time.Now()
	defer func() { metrics.ScanFinished(time.Since(start).Seconds()) }()

	tasks := r.store.Tasks()
	scans := r.store.Scans()

	selected := selectionNames(opts.Modules)

	// Result cache: reuse a recent scan whose modules superset-match (§7).
	if cached, ok := r.lookupCache(target.URL, selected); ok {
		slog.Info("scan served from cache", "task", taskID, "url", target.URL)
		b, _ := json.Marshal(cached)
		_ = tasks.SetResults(taskID, string(b))
		return cached, nil
	}

	_ = tasks.SetState(taskID, "PROGRESS", "")
	_ = tasks.SetCompletedModules(taskID, []string{})

	// Wire progress updates into the task row (drives SSE).
	opts.Progress = func(completed []string) {
		_ = tasks.SetCompletedModules(taskID, completed)
	}

	modResults := Run(ctx, target, r.cfg, r.client, opts)

	if err := ctx.Err(); err != nil {
		_ = tasks.SetState(taskID, "FAILURE", err.Error())
		return nil, err
	}

	results := assembleResults(target, selected, modResults)

	resultsJSON, _ := json.Marshal(results)
	scanID, err := scans.Insert(target.URL, string(resultsJSON))
	if err != nil {
		_ = tasks.SetState(taskID, "FAILURE", err.Error())
		return nil, err
	}

	meta, _ := results["_meta"].(map[string]any)
	meta["scan_id"] = scanID
	results["_meta"] = meta

	finalJSON, _ := json.Marshal(results)
	_ = tasks.SetResults(taskID, string(finalJSON))
	slog.Info("scan complete", "task", taskID, "scan_id", scanID, "url", target.URL)

	// Fire alerts to configured channels when risk meets the threshold.
	if sum, ok := results["_summary"].(map[string]any); ok {
		r.notifyIfNeeded(ctx, target.URL, scanID, sum)
	}
	return results, nil
}

func (r *Runner) notifyIfNeeded(ctx context.Context, url string, scanID int64, sum map[string]any) {
	r.notifier.NotifyScanComplete(ctx, notify.Summary{
		URL:       url,
		RiskScore: intOf(sum["risk_score"]),
		RiskLevel: stringOf(sum["risk_level"]),
		Findings:  intOf(sum["total_findings"]),
		ScanID:    scanID,
	})
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// lookupCache returns a cached result map when a recent scan covers at least the
// requested modules.
func (r *Runner) lookupCache(url string, requested []string) (map[string]any, bool) {
	sc, err := r.store.Scans().CachedWithin(url, r.cfg.CacheTTL)
	if err != nil {
		return nil, false
	}
	var cached map[string]any
	if err := json.Unmarshal([]byte(sc.Results), &cached); err != nil {
		return nil, false
	}
	meta, _ := cached["_meta"].(map[string]any)
	if meta == nil {
		return nil, false
	}
	cachedMods := toStringSet(meta["modules"])
	if len(cachedMods) == 0 {
		return nil, false
	}
	for _, m := range requested {
		if !cachedMods[m] {
			return nil, false
		}
	}
	meta["from_cache"] = true
	meta["scan_id"] = sc.ID
	cached["_meta"] = meta
	return cached, true
}

// assembleResults builds the results map: one entry per module's data plus a
// _meta block (target, modules, timing) matching the Python output shape.
func assembleResults(target safety.Target, modules []string, modResults map[string]ModuleResult) map[string]any {
	out := make(map[string]any, len(modResults)+1)
	statuses := make(map[string]string, len(modResults))
	var totalTime float64
	for name, res := range modResults {
		// The data map is what templates/exports consume per module.
		out[name] = res.Data
		statuses[name] = res.Status
		totalTime += res.ExecutionTime
		if res.Status != "success" && res.Error != "" {
			if dm, ok := out[name].(map[string]any); ok && dm != nil {
				dm["_status"] = res.Status
				dm["_error"] = res.Error
			} else {
				out[name] = map[string]any{"_status": res.Status, "_error": res.Error}
			}
		}
	}
	out["_meta"] = map[string]any{
		"target":        target.Raw,
		"url":           target.URL,
		"host":          target.Host,
		"kind":          string(target.Kind),
		"modules":       modules,
		"module_status": statuses,
		"total_time":    totalTime,
		"scan_date":     time.Now().Format(time.RFC3339),
		"from_cache":    false,
	}
	out["_summary"] = computeSummary(out)
	return out
}

// computeSummary aggregates findings into a risk score/level (drives the AI
// analysis, exporters, and UI badge).
func computeSummary(results map[string]any) map[string]any {
	findings := export.ExtractFindings(results)
	var counts ml.SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		default:
			counts.Info++
		}
	}
	score, level := ml.RiskScore(counts)
	summary := map[string]any{
		"risk_score":     score,
		"risk_level":     level,
		"total_findings": len(findings),
		"critical":       counts.Critical,
		"high":           counts.High,
		"medium":         counts.Medium,
		"low":            counts.Low,
	}
	// Surface a couple of metrics the AI analyst prompt references.
	if sh, ok := results["sec_headers"].(map[string]any); ok {
		summary["missing_sec_headers"] = sh["missing_sec_headers"]
	}
	if vt, ok := results["virustotal"].(map[string]any); ok {
		summary["vt_malicious"] = vt["malicious"]
	}
	return summary
}

// selectionNames returns the concrete module names that will run (expands the
// empty/"all" selection to every registered module).
func selectionNames(names []string) []string {
	if len(names) == 0 {
		return Names()
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, ok := Lookup(n); ok {
			out = append(out, n)
		}
	}
	return out
}

func toStringSet(v any) map[string]bool {
	set := map[string]bool{}
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			if s, ok := e.(string); ok {
				set[s] = true
			}
		}
	}
	return set
}

// RunMonitored runs a scan, then compares it to the previous scan of the same
// target and sends a change alert for any NEW findings (continuous monitoring).
// Intended to be launched in a goroutine by the scheduler.
func (r *Runner) RunMonitored(ctx context.Context, taskID string, target safety.Target, opts RunOptions) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("monitored scan panic", "task", taskID, "recover", rec)
		}
	}()
	results, err := r.RunTask(ctx, taskID, target, opts)
	if err != nil {
		return
	}
	meta, _ := results["_meta"].(map[string]any)
	scanID := int64Of(meta["scan_id"])
	if scanID == 0 {
		return
	}
	prevID, ok := r.store.Scans().PreviousForURL(target.URL, scanID)
	if !ok {
		return // first scan — nothing to diff against
	}
	prev, err := r.store.Scans().Get(prevID)
	if err != nil {
		return
	}
	var prevResults map[string]any
	if json.Unmarshal([]byte(prev.Results), &prevResults) != nil {
		return
	}

	old := findingTitles(prevResults)
	var added []string
	for _, f := range export.ExtractFindings(results) {
		key := f.Severity + ":" + f.Module + ":" + f.Title
		if !old[key] {
			added = append(added, fmt.Sprintf("[%s] %s (%s)", f.Severity, f.Title, f.Module))
		}
	}
	if len(added) > 0 {
		r.notifier.NotifyChanges(ctx, target.URL, added)
		slog.Info("monitoring detected changes", "url", target.URL, "new_findings", len(added))
	}
}

func findingTitles(results map[string]any) map[string]bool {
	set := map[string]bool{}
	for _, f := range export.ExtractFindings(results) {
		set[f.Severity+":"+f.Module+":"+f.Title] = true
	}
	return set
}

func int64Of(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

// StartTask creates a task row and runs the scan in a background goroutine tied
// to ctx. It returns immediately with the task id already persisted.
func (r *Runner) StartTask(ctx context.Context, taskID string, target safety.Target, opts RunOptions) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				_ = r.store.Tasks().SetState(taskID, "FAILURE", "panic in scan runner")
				slog.Error("scan runner panic", "task", taskID, "recover", rec)
			}
		}()
		if _, err := r.RunTask(ctx, taskID, target, opts); err != nil {
			slog.Error("scan task failed", "task", taskID, "err", err)
		}
	}()
}
