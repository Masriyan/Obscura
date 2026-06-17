package store

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestOpenEnablesWALAndSchema(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "obscura.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// WAL must be active.
	var mode string
	if err := st.DB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}

	// All 10 tables must exist.
	want := []string{
		"ai_conversations", "api_keys", "audit_log", "bulk_campaigns",
		"scan_notes", "scan_tags", "scan_templates", "scans",
		"scheduled_scans", "tasks",
	}
	rows, err := st.DB.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tables = %v, want %v", got, want)
	}

	// Migrations are idempotent: re-running migrate must not error.
	if err := st.migrate(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
}

func TestLegacyImport(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "aegis.db")
	dbPath := filepath.Join(dir, "obscura.db")

	// Seed a legacy DB with a recognizable row.
	seed, err := Open(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.DB.Exec("INSERT INTO scans(url, results, scan_date) VALUES('http://x','{}','2020-01-01')"); err != nil {
		t.Fatal(err)
	}
	seed.Close()

	// Opening obscura.db (absent) must import the legacy DB.
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy aegis.db should have been renamed away, stat err=%v", err)
	}
	var n int
	if err := st.DB.QueryRow("SELECT COUNT(*) FROM scans WHERE url='http://x'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("imported scan rows = %d, want 1 (history not preserved)", n)
	}
}

func TestNoLegacyImportWhenTargetExists(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "aegis.db")
	dbPath := filepath.Join(dir, "obscura.db")

	// Create the target obscura.db FIRST so it already exists, then a legacy
	// aegis.db alongside it. Re-opening must NOT import (no rename).
	s1, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := Open(legacy)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()

	s3, err := Open(dbPath) // obscura.db already exists -> must skip import
	if err != nil {
		t.Fatal(err)
	}
	s3.Close()

	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy aegis.db must remain when obscura.db already exists: %v", err)
	}
}
