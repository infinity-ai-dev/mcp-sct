package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements Store using SQLite for self-hosted persistence.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite-backed store.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			path TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			files_scanned INTEGER DEFAULT 0,
			finding_count INTEGER DEFAULT 0,
			critical INTEGER DEFAULT 0,
			high INTEGER DEFAULT 0,
			medium INTEGER DEFAULT 0,
			low INTEGER DEFAULT 0,
			findings_json TEXT,
			deps_json TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id, timestamp DESC);

		CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			hash TEXT NOT NULL UNIQUE,
			name TEXT,
			created_at TEXT NOT NULL,
			expires_at TEXT,
			scopes_json TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(hash);
		CREATE INDEX IF NOT EXISTS idx_tokens_project ON tokens(project_id);
	`)
	return err
}

func (s *SQLiteStore) SaveScan(ctx context.Context, record *ScanRecord) error {
	if record.ID == "" {
		record.ID = genID()
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}

	findingsJSON, _ := json.Marshal(record.Findings)
	depsJSON, _ := json.Marshal(record.DepsResults)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (id, project_id, path, timestamp, files_scanned, finding_count, critical, high, medium, low, findings_json, deps_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.ID,
		record.ProjectID,
		record.Path,
		record.Timestamp.Format(time.RFC3339),
		record.FilesScanned,
		record.FindingCount,
		record.Critical,
		record.High,
		record.Medium,
		record.Low,
		string(findingsJSON),
		string(depsJSON),
	)
	return err
}

func (s *SQLiteStore) GetScan(ctx context.Context, id string) (*ScanRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, path, timestamp, files_scanned, finding_count, critical, high, medium, low, findings_json, deps_json
		FROM scans WHERE id = ?
	`, id)

	return scanRow(row)
}

func (s *SQLiteStore) ListScans(ctx context.Context, projectID string, limit int) ([]*ScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, path, timestamp, files_scanned, finding_count, critical, high, medium, low, findings_json, deps_json
		FROM scans WHERE project_id = ? ORDER BY timestamp DESC LIMIT ?
	`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		r, err := scanRows(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func scanRow(row *sql.Row) (*ScanRecord, error) {
	var r ScanRecord
	var ts, findingsJSON, depsJSON string

	err := row.Scan(&r.ID, &r.ProjectID, &r.Path, &ts,
		&r.FilesScanned, &r.FindingCount, &r.Critical, &r.High, &r.Medium, &r.Low,
		&findingsJSON, &depsJSON)
	if err != nil {
		return nil, err
	}

	r.Timestamp, _ = time.Parse(time.RFC3339, ts)
	json.Unmarshal([]byte(findingsJSON), &r.Findings)
	json.Unmarshal([]byte(depsJSON), &r.DepsResults)

	return &r, nil
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanRows(row scannable) (*ScanRecord, error) {
	var r ScanRecord
	var ts, findingsJSON, depsJSON string

	err := row.Scan(&r.ID, &r.ProjectID, &r.Path, &ts,
		&r.FilesScanned, &r.FindingCount, &r.Critical, &r.High, &r.Medium, &r.Low,
		&findingsJSON, &depsJSON)
	if err != nil {
		return nil, err
	}

	r.Timestamp, _ = time.Parse(time.RFC3339, ts)
	json.Unmarshal([]byte(findingsJSON), &r.Findings)
	json.Unmarshal([]byte(depsJSON), &r.DepsResults)

	return &r, nil
}

func genID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
