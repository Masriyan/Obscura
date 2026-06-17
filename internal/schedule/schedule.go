// Package schedule runs recurring scans from the scheduled_scans table. The
// schema is interval-based (every N minutes), so this uses a lightweight ticker
// that dispatches due schedules through the engine Runner — no cron expression
// parser is needed (noted in MIGRATION_NOTES vs the APScheduler original).
package schedule

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"obscurascan/internal/engine"
	"obscurascan/internal/safety"
	"obscurascan/internal/store"
)

// Scheduler dispatches due scheduled scans.
type Scheduler struct {
	store  *store.Store
	runner *engine.Runner
	tick   time.Duration
}

// New builds a Scheduler. tick controls how often the table is polled.
func New(st *store.Store, runner *engine.Runner) *Scheduler {
	return &Scheduler{store: st, runner: runner, tick: 30 * time.Second}
}

// Start runs the scheduler loop until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	t := time.NewTicker(s.tick)
	defer t.Stop()
	slog.Info("scheduler started", "poll", s.tick.String())
	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler stopped")
			return
		case <-t.C:
			s.runDue(ctx)
		}
	}
}

func (s *Scheduler) runDue(ctx context.Context) {
	due, err := s.store.Schedules().Due()
	if err != nil {
		slog.Warn("scheduler: list due failed", "err", err)
		return
	}
	for _, sc := range due {
		if ctx.Err() != nil {
			return
		}
		target, err := safety.ValidateTarget(sc.URL)
		if err != nil {
			slog.Warn("scheduler: invalid target, skipping", "url", sc.URL, "err", err)
			_ = s.store.Schedules().MarkRun(sc.ID, sc.IntervalMinutes)
			continue
		}
		var modules []string
		_ = json.Unmarshal([]byte(sc.Services), &modules)

		taskID := uuid.NewString()
		if err := s.store.Tasks().Create(taskID, target.URL); err != nil {
			slog.Warn("scheduler: task create failed", "err", err)
			continue
		}
		slog.Info("scheduler: dispatching scan", "schedule_id", sc.ID, "url", target.URL, "task", taskID)
		// Monitored run: scans, then diffs vs the previous scan and alerts on
		// any new findings (continuous monitoring).
		go s.runner.RunMonitored(ctx, taskID, target, engine.RunOptions{Modules: modules, Mode: sc.Mode})
		_ = s.store.Schedules().MarkRun(sc.ID, sc.IntervalMinutes)
	}
}
