package sources

import (
	"context"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// VulnSource queries vulnerability databases for known CVEs.
type VulnSource interface {
	Name() string
	Query(ctx context.Context, dependencies []deps.Dependency) ([]deps.VulnMatch, error)
}
