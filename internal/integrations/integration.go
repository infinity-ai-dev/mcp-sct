package integrations

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ExternalTool wraps an external security analysis tool.
type ExternalTool interface {
	Name() string
	IsInstalled() bool
	Run(ctx context.Context, path string) (*ToolResult, error)
}

// ToolResult holds the output of an external tool run.
type ToolResult struct {
	Tool     string `json:"tool"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
}

// runCommand executes a command with timeout and returns the result.
func runCommand(ctx context.Context, name string, args ...string) (*ToolResult, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := &ToolResult{
		Tool:     name,
		Output:   stdout.String(),
		Error:    stderr.String(),
		Duration: duration.Round(time.Millisecond).String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed to run %s: %w", name, err)
		}
	}

	return result, nil
}

// isCommandAvailable checks if a command exists in PATH.
func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// FormatToolResult formats an external tool result as markdown.
func FormatToolResult(r *ToolResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### %s\n\n", r.Tool))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n", r.Duration))
	sb.WriteString(fmt.Sprintf("**Exit code:** %d\n\n", r.ExitCode))

	if r.Output != "" {
		// Truncate very long output
		output := r.Output
		if len(output) > 5000 {
			output = output[:5000] + "\n... (truncated)"
		}
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	if r.Error != "" && r.ExitCode != 0 {
		sb.WriteString(fmt.Sprintf("\n**Errors:**\n```\n%s\n```\n", r.Error))
	}

	return sb.String()
}
