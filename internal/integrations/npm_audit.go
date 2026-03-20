package integrations

import (
	"context"
	"os"
	"path/filepath"
)

// NPMAudit wraps npm audit.
type NPMAudit struct{}

func (n *NPMAudit) Name() string { return "npm audit" }

func (n *NPMAudit) IsInstalled() bool {
	return isCommandAvailable("npm")
}

func (n *NPMAudit) Run(ctx context.Context, path string) (*ToolResult, error) {
	// Check if package.json exists
	if _, err := os.Stat(filepath.Join(path, "package.json")); err != nil {
		return &ToolResult{
			Tool:   "npm audit",
			Output: "No package.json found, skipping npm audit.",
		}, nil
	}

	result, err := runCommand(ctx, "npm", "audit", "--json", "--prefix", path)
	if err != nil {
		return nil, err
	}
	result.Tool = "npm audit"
	return result, nil
}
