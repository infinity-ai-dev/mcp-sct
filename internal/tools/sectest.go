package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mcp-sct/mcp-sct/internal/integrations"
)

// RunSecurityTestHandler handles the run_security_test tool.
type RunSecurityTestHandler struct {
	tools []integrations.ExternalTool
}

func NewRunSecurityTestHandler() *RunSecurityTestHandler {
	return &RunSecurityTestHandler{
		tools: []integrations.ExternalTool{
			&integrations.Semgrep{},
			&integrations.Bandit{},
			&integrations.GoSec{},
			&integrations.NPMAudit{},
		},
	}
}

type RunSecurityTestArgs struct {
	Path    string `json:"path"`
	Tool    string `json:"tool,omitempty"`     // specific tool to run
	Timeout int    `json:"timeout,omitempty"`  // seconds
}

func (h *RunSecurityTestHandler) Handle(ctx context.Context, args RunSecurityTestArgs) (string, error) {
	if args.Path == "" {
		return "", fmt.Errorf("path is required")
	}

	timeout := 120 * time.Second
	if args.Timeout > 0 {
		timeout = time.Duration(args.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var sb strings.Builder
	sb.WriteString("## MCP-SCT External Security Tests\n\n")
	sb.WriteString(fmt.Sprintf("**Path:** `%s`\n\n", args.Path))

	// Filter to specific tool or run all available
	toolsToRun := h.tools
	if args.Tool != "" {
		toolsToRun = nil
		for _, t := range h.tools {
			if strings.EqualFold(t.Name(), args.Tool) {
				toolsToRun = append(toolsToRun, t)
				break
			}
		}
		if len(toolsToRun) == 0 {
			return "", fmt.Errorf("unknown tool: %s (available: %s)", args.Tool, h.listAvailable())
		}
	}

	// Check which tools are installed
	available := make([]integrations.ExternalTool, 0)
	notInstalled := make([]string, 0)
	for _, t := range toolsToRun {
		if t.IsInstalled() {
			available = append(available, t)
		} else {
			notInstalled = append(notInstalled, t.Name())
		}
	}

	if len(available) == 0 {
		sb.WriteString("No external security tools found installed.\n\n")
		sb.WriteString("**Install one of these tools to use this feature:**\n")
		sb.WriteString("- `pip install semgrep` - Multi-language static analysis\n")
		sb.WriteString("- `pip install bandit` - Python security linter\n")
		sb.WriteString("- `go install github.com/securego/gosec/v2/cmd/gosec@latest` - Go security checker\n")
		sb.WriteString("- `npm` (built-in) - npm audit for JS dependencies\n")
		return sb.String(), nil
	}

	if len(notInstalled) > 0 {
		sb.WriteString(fmt.Sprintf("*Not installed: %s*\n\n", strings.Join(notInstalled, ", ")))
	}

	// Run each available tool
	for _, t := range available {
		sb.WriteString(fmt.Sprintf("Running **%s**...\n\n", t.Name()))

		result, err := t.Run(ctx, args.Path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("**%s** failed: %v\n\n", t.Name(), err))
			continue
		}

		sb.WriteString(integrations.FormatToolResult(result))
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func (h *RunSecurityTestHandler) listAvailable() string {
	names := make([]string, len(h.tools))
	for i, t := range h.tools {
		names[i] = t.Name()
	}
	return strings.Join(names, ", ")
}
