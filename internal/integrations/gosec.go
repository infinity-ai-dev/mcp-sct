package integrations

import "context"

// GoSec wraps the Go security checker (gosec).
type GoSec struct{}

func (g *GoSec) Name() string { return "gosec" }

func (g *GoSec) IsInstalled() bool {
	return isCommandAvailable("gosec")
}

func (g *GoSec) Run(ctx context.Context, path string) (*ToolResult, error) {
	result, err := runCommand(ctx, "gosec",
		"-fmt", "json",
		"-quiet",
		path+"/...",
	)
	if err != nil {
		return nil, err
	}
	result.Tool = "gosec"
	return result, nil
}
