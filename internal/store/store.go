// Package store is the SQLite persistence layer for Obscura Scan.
//
// It uses modernc.org/sqlite (pure Go, keeps CGO_ENABLED=0), opens the database
// in WAL mode, and runs idempotent migrations on startup. The schema is a
// faithful reproduction of the Python AEGIS schema (aegis.py init_db + the
// enterprise tables in core/enterprise.py).
package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store wraps the database handle and exposes repositories.
type Store struct {
	DB *sql.DB
}

// schema reproduces the 5 core tables (aegis.py) + 5 enterprise tables
// (core/enterprise.py) exactly, as idempotent CREATE TABLE IF NOT EXISTS.
const schema = `
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'PENDING',
    completed_modules TEXT DEFAULT '[]',
    results TEXT,
    error TEXT,
    scan_date TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    results TEXT NOT NULL,
    scan_date TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    services TEXT NOT NULL,
    mode TEXT NOT NULL,
    extras TEXT,
    interval_minutes INTEGER NOT NULL,
    next_run TEXT NOT NULL,
    last_run TEXT,
    last_results TEXT
);
CREATE TABLE IF NOT EXISTS ai_conversations (
    id TEXT PRIMARY KEY,
    scan_id INTEGER,
    messages TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS scan_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_notes_scan_id ON scan_notes(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);
CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_scan_date ON tasks(scan_date);

-- Enterprise tables (core/enterprise.py)
CREATE TABLE IF NOT EXISTS scan_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    UNIQUE(scan_id, tag),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_tags_tag ON scan_tags(tag);
CREATE INDEX IF NOT EXISTS idx_scan_tags_scan ON scan_tags(scan_id);
CREATE TABLE IF NOT EXISTS scan_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    modules TEXT NOT NULL DEFAULT '[]',
    mode TEXT NOT NULL DEFAULT 'passive',
    created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'viewer',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    user TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE TABLE IF NOT EXISTS bulk_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    targets TEXT NOT NULL DEFAULT '[]',
    template TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    results TEXT DEFAULT '{}'
);
`

// Open opens (or creates) the database at dbPath in WAL mode and runs
// migrations. If dbPath is absent but a legacy aegis.db exists in the same
// directory, it is imported (renamed) first so existing scan history is kept.
func Open(dbPath string) (*Store, error) {
	importLegacy(dbPath)

	// modernc.org/sqlite honors PRAGMAs supplied as connection query params.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// importLegacy renames a legacy aegis.db (+WAL/SHM sidecars) to the new path
// when the new DB does not yet exist, preserving scan history.
func importLegacy(dbPath string) {
	if _, err := os.Stat(dbPath); err == nil {
		return // new DB already exists; nothing to import
	}
	legacy := filepath.Join(filepath.Dir(dbPath), "aegis.db")
	if dbPath == legacy {
		return
	}
	if _, err := os.Stat(legacy); err != nil {
		return // no legacy DB present
	}
	if err := os.Rename(legacy, dbPath); err != nil {
		slog.Warn("legacy import failed", "from", legacy, "to", dbPath, "err", err)
		return
	}
	// Move WAL/SHM sidecars if present so the imported DB is consistent.
	for _, suffix := range []string{"-wal", "-shm"} {
		src, dst := legacy+suffix, dbPath+suffix
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	slog.Info("imported legacy AEGIS database", "from", legacy, "to", dbPath)
}

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(schema); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s.DB == nil {
		return nil
	}
	return s.DB.Close()
}
