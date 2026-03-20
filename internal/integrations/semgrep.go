package integrations

import "context"

// Semgrep wraps the semgrep CLI tool.
type Semgrep struct{}

func (s *Semgrep) Name() string { return "semgrep" }

func (s *Semgrep) IsInstalled() bool {
	return isCommandAvailable("semgrep")
}

func (s *Semgrep) Run(ctx context.Context, path string) (*ToolResult, error) {
	result, err := runCommand(ctx, "semgrep", "scan",
		"--config", "auto",
		"--json",
		"--quiet",
		path,
	)
	if err != nil {
		return nil, err
	}
	result.Tool = "semgrep"
	return result, nil
}
