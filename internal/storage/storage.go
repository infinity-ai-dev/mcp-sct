package storage

import (
	"context"
	"time"

	"github.com/mcp-sct/mcp-sct/internal/deps"
	"github.com/mcp-sct/mcp-sct/internal/types"
)

// ScanRecord represents a persisted scan result.
type ScanRecord struct {
	ID           string            `json:"id"`
	ProjectID    string            `json:"project_id"`
	Path         string            `json:"path"`
	Timestamp    time.Time         `json:"timestamp"`
	FilesScanned int               `json:"files_scanned"`
	FindingCount int               `json:"finding_count"`
	Critical     int               `json:"critical"`
	High         int               `json:"high"`
	Medium       int               `json:"medium"`
	Low          int               `json:"low"`
	Findings     []types.Finding   `json:"findings,omitempty"`
	DepsResults  []deps.CheckResult `json:"deps_results,omitempty"`
}

// Store provides persistence for scan results and project data.
type Store interface {
	// SaveScan persists a scan result.
	SaveScan(ctx context.Context, record *ScanRecord) error
	// GetScan retrieves a scan by ID.
	GetScan(ctx context.Context, id string) (*ScanRecord, error)
	// ListScans returns recent scans for a project.
	ListScans(ctx context.Context, projectID string, limit int) ([]*ScanRecord, error)
	// Close releases resources.
	Close() error
}
