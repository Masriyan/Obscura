package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Task mirrors a row in the tasks table.
type Task struct {
	ID               string
	URL              string
	State            string
	CompletedModules []string
	Results          string // raw JSON
	Error            string
	ScanDate         time.Time
}

// TaskRepo persists scan task state (drives SSE + status bar).
type TaskRepo struct{ db *sql.DB }

// Tasks returns the task repository.
func (s *Store) Tasks() *TaskRepo { return &TaskRepo{db: s.DB} }

// Create inserts a new PENDING task.
func (r *TaskRepo) Create(id, url string) error {
	_, err := r.db.Exec(
		`INSERT INTO tasks (id, url, state, completed_modules, scan_date) VALUES (?, ?, 'PENDING', '[]', ?)`,
		id, url, time.Now().Format(time.RFC3339),
	)
	return err
}

// SetState updates a task's state and, optionally, its error message.
func (r *TaskRepo) SetState(id, state, errMsg string) error {
	_, err := r.db.Exec(`UPDATE tasks SET state=?, error=? WHERE id=?`, state, nullable(errMsg), id)
	return err
}

// SetCompletedModules records progress as a JSON array.
func (r *TaskRepo) SetCompletedModules(id string, modules []string) error {
	b, _ := json.Marshal(modules)
	_, err := r.db.Exec(`UPDATE tasks SET completed_modules=? WHERE id=?`, string(b), id)
	return err
}

// SetResults stores the final results JSON and marks the task SUCCESS.
func (r *TaskRepo) SetResults(id, resultsJSON string) error {
	_, err := r.db.Exec(`UPDATE tasks SET state='SUCCESS', results=? WHERE id=?`, resultsJSON, id)
	return err
}

// Get loads a task by id.
func (r *TaskRepo) Get(id string) (*Task, error) {
	row := r.db.QueryRow(
		`SELECT id, url, state, completed_modules, COALESCE(results,''), COALESCE(error,''), scan_date FROM tasks WHERE id=?`, id)
	var t Task
	var completed, scanDate string
	if err := row.Scan(&t.ID, &t.URL, &t.State, &completed, &t.Results, &t.Error, &scanDate); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(completed), &t.CompletedModules)
	t.ScanDate, _ = time.Parse(time.RFC3339, scanDate)
	return &t, nil
}

// ActiveCount returns the number of tasks not in a terminal state.
func (r *TaskRepo) ActiveCount() (int, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE state IN ('PENDING','PROGRESS')`).Scan(&n)
	return n, err
}

// Scan mirrors a row in the scans table.
type Scan struct {
	ID       int64
	URL      string
	Results  string // raw JSON
	ScanDate time.Time
}

// ScanRepo persists completed scan results.
type ScanRepo struct{ db *sql.DB }

// Scans returns the scan repository.
func (s *Store) Scans() *ScanRepo { return &ScanRepo{db: s.DB} }

// Insert stores a completed scan and returns its new id.
func (r *ScanRepo) Insert(url, resultsJSON string) (int64, error) {
	res, err := r.db.Exec(
		`INSERT INTO scans (url, results, scan_date) VALUES (?, ?, ?)`,
		url, resultsJSON, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Get loads a scan by id.
func (r *ScanRepo) Get(id int64) (*Scan, error) {
	row := r.db.QueryRow(`SELECT id, url, results, scan_date FROM scans WHERE id=?`, id)
	var s Scan
	var scanDate string
	if err := row.Scan(&s.ID, &s.URL, &s.Results, &scanDate); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.ScanDate, _ = time.Parse(time.RFC3339, scanDate)
	return &s, nil
}

// CachedWithin returns the most recent scan for url newer than ttlSeconds, or
// ErrNotFound. Module-superset matching is applied by the caller.
func (r *ScanRepo) CachedWithin(url string, ttlSeconds int) (*Scan, error) {
	if ttlSeconds <= 0 {
		return nil, ErrNotFound
	}
	cutoff := time.Now().Add(-time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339)
	row := r.db.QueryRow(
		`SELECT id, url, results, scan_date FROM scans WHERE url=? AND scan_date >= ? ORDER BY id DESC LIMIT 1`,
		url, cutoff)
	var s Scan
	var scanDate string
	if err := row.Scan(&s.ID, &s.URL, &s.Results, &scanDate); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.ScanDate, _ = time.Parse(time.RFC3339, scanDate)
	return &s, nil
}

// List returns recent scans (id, url, date) up to limit, newest first.
func (r *ScanRepo) List(limit int) ([]Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(`SELECT id, url, scan_date FROM scans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var s Scan
		var scanDate string
		if err := rows.Scan(&s.ID, &s.URL, &scanDate); err != nil {
			return nil, err
		}
		s.ScanDate, _ = time.Parse(time.RFC3339, scanDate)
		out = append(out, s)
	}
	return out, rows.Err()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ScheduledScan mirrors a row in the scheduled_scans table.
type ScheduledScan struct {
	ID              int64
	URL             string
	Services        string // JSON array of module names
	Mode            string
	Extras          string
	IntervalMinutes int
	NextRun         time.Time
	LastRun         *time.Time
}

// ScheduleRepo manages recurring scans.
type ScheduleRepo struct{ db *sql.DB }

// Schedules returns the schedule repository.
func (s *Store) Schedules() *ScheduleRepo { return &ScheduleRepo{db: s.DB} }

// Create inserts a scheduled scan, due immediately by default.
func (r *ScheduleRepo) Create(url, services, mode string, intervalMinutes int) (int64, error) {
	res, err := r.db.Exec(
		`INSERT INTO scheduled_scans (url, services, mode, interval_minutes, next_run) VALUES (?, ?, ?, ?, ?)`,
		url, services, mode, intervalMinutes, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Delete removes a scheduled scan.
func (r *ScheduleRepo) Delete(id int64) error {
	_, err := r.db.Exec(`DELETE FROM scheduled_scans WHERE id=?`, id)
	return err
}

// List returns all scheduled scans, soonest next_run first.
func (r *ScheduleRepo) List() ([]ScheduledScan, error) {
	rows, err := r.db.Query(`SELECT id, url, services, mode, COALESCE(extras,''), interval_minutes, next_run, last_run FROM scheduled_scans ORDER BY next_run ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScheduledScan
	for rows.Next() {
		var s ScheduledScan
		var nextRun string
		var lastRun sql.NullString
		if err := rows.Scan(&s.ID, &s.URL, &s.Services, &s.Mode, &s.Extras, &s.IntervalMinutes, &nextRun, &lastRun); err != nil {
			return nil, err
		}
		s.NextRun, _ = time.Parse(time.RFC3339, nextRun)
		if lastRun.Valid {
			if t, err := time.Parse(time.RFC3339, lastRun.String); err == nil {
				s.LastRun = &t
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Due returns schedules whose next_run is in the past.
func (r *ScheduleRepo) Due() ([]ScheduledScan, error) {
	all, err := r.List()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var due []ScheduledScan
	for _, s := range all {
		if !s.NextRun.After(now) {
			due = append(due, s)
		}
	}
	return due, nil
}

// MarkRun records a run and advances next_run by the interval.
func (r *ScheduleRepo) MarkRun(id int64, intervalMinutes int) error {
	now := time.Now()
	next := now.Add(time.Duration(intervalMinutes) * time.Minute)
	_, err := r.db.Exec(`UPDATE scheduled_scans SET last_run=?, next_run=? WHERE id=?`,
		now.Format(time.RFC3339), next.Format(time.RFC3339), id)
	return err
}

// LatestForURL returns the most recent scan for url, or (nil,false).
func (r *ScanRepo) LatestForURL(url string) (*Scan, bool) {
	row := r.db.QueryRow(`SELECT id, url, results, scan_date FROM scans WHERE url=? ORDER BY id DESC LIMIT 1`, url)
	var s Scan
	var scanDate string
	if err := row.Scan(&s.ID, &s.URL, &s.Results, &scanDate); err != nil {
		return nil, false
	}
	s.ScanDate, _ = time.Parse(time.RFC3339, scanDate)
	return &s, true
}

// PreviousForURL returns the id of the most recent scan for url older than
// beforeID, or (0, false) if there is none. Used by scan compare.
func (r *ScanRepo) PreviousForURL(url string, beforeID int64) (int64, bool) {
	var id int64
	err := r.db.QueryRow(
		`SELECT id FROM scans WHERE url=? AND id < ? ORDER BY id DESC LIMIT 1`, url, beforeID).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// Note mirrors a row in the scan_notes table.
type Note struct {
	ID        int64
	ScanID    int64
	Note      string
	Author    string
	CreatedAt time.Time
}

// NotesRepo manages analyst notes attached to scans.
type NotesRepo struct{ db *sql.DB }

// Notes returns the notes repository.
func (s *Store) Notes() *NotesRepo { return &NotesRepo{db: s.DB} }

// Add inserts a note and returns its id.
func (r *NotesRepo) Add(scanID int64, note, author string) (int64, error) {
	if author == "" {
		author = "analyst"
	}
	res, err := r.db.Exec(
		`INSERT INTO scan_notes (scan_id, note, author, created_at) VALUES (?, ?, ?, ?)`,
		scanID, note, author, time.Now().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// List returns the notes for a scan, newest first.
func (r *NotesRepo) List(scanID int64) ([]Note, error) {
	rows, err := r.db.Query(
		`SELECT id, scan_id, note, author, created_at FROM scan_notes WHERE scan_id=? ORDER BY id DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		var n Note
		var created string
		if err := rows.Scan(&n.ID, &n.ScanID, &n.Note, &n.Author, &created); err != nil {
			return nil, err
		}
		n.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, n)
	}
	return out, rows.Err()
}

// Delete removes a note.
func (r *NotesRepo) Delete(id int64) error {
	_, err := r.db.Exec(`DELETE FROM scan_notes WHERE id=?`, id)
	return err
}

// APIKey mirrors a row in the api_keys table (the secret is never stored).
type APIKey struct {
	ID        int64
	Name      string
	Role      string
	Active    bool
	CreatedAt time.Time
	LastUsed  *time.Time
}

// APIKeyRepo manages bearer API keys for the REST API.
type APIKeyRepo struct{ db *sql.DB }

// APIKeys returns the API-key repository.
func (s *Store) APIKeys() *APIKeyRepo { return &APIKeyRepo{db: s.DB} }

// Create stores a key by its hash (caller mints + hashes the plaintext).
func (r *APIKeyRepo) Create(name, keyHash, role string) (int64, error) {
	if role == "" {
		role = "viewer"
	}
	res, err := r.db.Exec(
		`INSERT INTO api_keys (name, key_hash, role, active, created_at) VALUES (?, ?, ?, 1, ?)`,
		name, keyHash, role, time.Now().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Lookup resolves an active key by its hash, returning name+role, and updates
// last_used. Returns ok=false when the key is unknown or inactive.
func (r *APIKeyRepo) Lookup(keyHash string) (name, role string, ok bool) {
	row := r.db.QueryRow(`SELECT name, role FROM api_keys WHERE key_hash=? AND active=1`, keyHash)
	if err := row.Scan(&name, &role); err != nil {
		return "", "", false
	}
	_, _ = r.db.Exec(`UPDATE api_keys SET last_used=? WHERE key_hash=?`, time.Now().Format(time.RFC3339), keyHash)
	return name, role, true
}

// List returns all API keys (no secrets).
func (r *APIKeyRepo) List() ([]APIKey, error) {
	rows, err := r.db.Query(`SELECT id, name, role, active, created_at, last_used FROM api_keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var active int
		var created string
		var lastUsed sql.NullString
		if err := rows.Scan(&k.ID, &k.Name, &k.Role, &active, &created, &lastUsed); err != nil {
			return nil, err
		}
		k.Active = active == 1
		k.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if lastUsed.Valid {
			if t, err := time.Parse(time.RFC3339, lastUsed.String); err == nil {
				k.LastUsed = &t
			}
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// AuditEntry mirrors a row in the audit_log table.
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	User      string
	Action    string
	Details   string
	IP        string
}

// AuditRepo persists API audit events.
type AuditRepo struct{ db *sql.DB }

// Audit returns the audit-log repository.
func (s *Store) Audit() *AuditRepo { return &AuditRepo{db: s.DB} }

// Log records an audit event.
func (r *AuditRepo) Log(user, action, details, ip string) {
	_, _ = r.db.Exec(
		`INSERT INTO audit_log (timestamp, user, action, details, ip) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Format(time.RFC3339), user, action, details, ip)
}

// ScanTemplate is a named module preset.
type ScanTemplate struct {
	ID          int64
	Name        string
	Description string
	Modules     []string
	Mode        string
}

// TemplateRepo manages scan templates/profiles.
type TemplateRepo struct{ db *sql.DB }

// Templates returns the template repository.
func (s *Store) Templates() *TemplateRepo { return &TemplateRepo{db: s.DB} }

// Upsert inserts or updates a template by name.
func (r *TemplateRepo) Upsert(name, desc string, modules []string, mode string) error {
	b, _ := json.Marshal(modules)
	_, err := r.db.Exec(
		`INSERT INTO scan_templates (name, description, modules, mode, created_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET description=excluded.description, modules=excluded.modules, mode=excluded.mode`,
		name, desc, string(b), mode, time.Now().Format(time.RFC3339))
	return err
}

// List returns all templates.
func (r *TemplateRepo) List() ([]ScanTemplate, error) {
	rows, err := r.db.Query(`SELECT id, name, COALESCE(description,''), modules, mode FROM scan_templates ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanTemplate
	for rows.Next() {
		var t ScanTemplate
		var mods string
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &mods, &t.Mode); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(mods), &t.Modules)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Count returns how many templates exist (used to seed defaults once).
func (r *TemplateRepo) Count() int {
	var n int
	_ = r.db.QueryRow(`SELECT COUNT(*) FROM scan_templates`).Scan(&n)
	return n
}

// Campaign is a bulk multi-target scan.
type Campaign struct {
	ID          int64
	Name        string
	Targets     []string
	Status      string
	CreatedAt   time.Time
	CompletedAt *time.Time
	Results     map[string]any // target -> {scan_id, risk, ...}
}

// CampaignRepo manages bulk campaigns.
type CampaignRepo struct{ db *sql.DB }

// Campaigns returns the campaign repository.
func (s *Store) Campaigns() *CampaignRepo { return &CampaignRepo{db: s.DB} }

// Create inserts a campaign and returns its id.
func (r *CampaignRepo) Create(name string, targets []string) (int64, error) {
	tb, _ := json.Marshal(targets)
	res, err := r.db.Exec(
		`INSERT INTO bulk_campaigns (name, targets, status, created_at, results) VALUES (?, ?, 'running', ?, '{}')`,
		name, string(tb), time.Now().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetResults updates a campaign's per-target results map and status.
func (r *CampaignRepo) SetResults(id int64, results map[string]any, status string) error {
	rb, _ := json.Marshal(results)
	completed := sql.NullString{}
	if status == "completed" {
		completed = sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true}
	}
	_, err := r.db.Exec(`UPDATE bulk_campaigns SET results=?, status=?, completed_at=? WHERE id=?`,
		string(rb), status, completed, id)
	return err
}

// Get loads a campaign by id.
func (r *CampaignRepo) Get(id int64) (*Campaign, error) {
	row := r.db.QueryRow(`SELECT id, name, targets, status, created_at, completed_at, results FROM bulk_campaigns WHERE id=?`, id)
	return scanCampaign(row)
}

// List returns campaigns, newest first.
func (r *CampaignRepo) List() ([]Campaign, error) {
	rows, err := r.db.Query(`SELECT id, name, targets, status, created_at, completed_at, results FROM bulk_campaigns ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCampaign(row scanner) (*Campaign, error) {
	var c Campaign
	var targets, results, created string
	var completed sql.NullString
	if err := row.Scan(&c.ID, &c.Name, &targets, &c.Status, &created, &completed, &results); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(targets), &c.Targets)
	_ = json.Unmarshal([]byte(results), &c.Results)
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if completed.Valid {
		if t, err := time.Parse(time.RFC3339, completed.String); err == nil {
			c.CompletedAt = &t
		}
	}
	return &c, nil
}

// Recent returns the most recent audit entries.
func (r *AuditRepo) Recent(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.Query(
		`SELECT id, timestamp, COALESCE(user,''), action, COALESCE(details,''), COALESCE(ip,'') FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.User, &e.Action, &e.Details, &e.IP); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
