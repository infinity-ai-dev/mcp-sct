package integrations

import "context"

// Bandit wraps the Python Bandit security linter.
type Bandit struct{}

func (b *Bandit) Name() string { return "bandit" }

func (b *Bandit) IsInstalled() bool {
	return isCommandAvailable("bandit")
}

func (b *Bandit) Run(ctx context.Context, path string) (*ToolResult, error) {
	result, err := runCommand(ctx, "bandit",
		"-r",
		"-f", "json",
		"-ll",
		path,
	)
	if err != nil {
		return nil, err
	}
	result.Tool = "bandit"
	return result, nil
}
