package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a PostgreSQL-backed store.
func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres ping failed: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) SaveScan(ctx context.Context, record *ScanRecord) error {
	if record.ID == "" {
		record.ID = pgGenID()
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}

	findingsJSON, _ := json.Marshal(record.Findings)
	depsJSON, _ := json.Marshal(record.DepsResults)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (id, project_id, path, timestamp, files_scanned, finding_count, critical, high, medium, low, findings_json, deps_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		record.ID,
		record.ProjectID,
		record.Path,
		record.Timestamp,
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

func (s *PostgresStore) GetScan(ctx context.Context, id string) (*ScanRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, path, timestamp, files_scanned, finding_count, critical, high, medium, low, findings_json, deps_json
		FROM scans WHERE id = $1
	`, id)

	return pgScanRow(row)
}

func (s *PostgresStore) ListScans(ctx context.Context, projectID string, limit int) ([]*ScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, path, timestamp, files_scanned, finding_count, critical, high, medium, low, findings_json, deps_json
		FROM scans WHERE project_id = $1 ORDER BY timestamp DESC LIMIT $2
	`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		r, err := pgScanRows(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func pgScanRow(row *sql.Row) (*ScanRecord, error) {
	var r ScanRecord
	var ts time.Time
	var findingsJSON, depsJSON string

	err := row.Scan(&r.ID, &r.ProjectID, &r.Path, &ts,
		&r.FilesScanned, &r.FindingCount, &r.Critical, &r.High, &r.Medium, &r.Low,
		&findingsJSON, &depsJSON)
	if err != nil {
		return nil, err
	}

	r.Timestamp = ts
	json.Unmarshal([]byte(findingsJSON), &r.Findings)
	json.Unmarshal([]byte(depsJSON), &r.DepsResults)

	return &r, nil
}

func pgScanRows(rows *sql.Rows) (*ScanRecord, error) {
	var r ScanRecord
	var ts time.Time
	var findingsJSON, depsJSON string

	err := rows.Scan(&r.ID, &r.ProjectID, &r.Path, &ts,
		&r.FilesScanned, &r.FindingCount, &r.Critical, &r.High, &r.Medium, &r.Low,
		&findingsJSON, &depsJSON)
	if err != nil {
		return nil, err
	}

	r.Timestamp = ts
	json.Unmarshal([]byte(findingsJSON), &r.Findings)
	json.Unmarshal([]byte(depsJSON), &r.DepsResults)

	return &r, nil
}

func pgGenID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
