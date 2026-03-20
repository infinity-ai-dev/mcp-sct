package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// CheckDepsHandler handles the check_dependencies tool.
type CheckDepsHandler struct {
	checker *deps.Checker
}

func NewCheckDepsHandler(checker *deps.Checker) *CheckDepsHandler {
	return &CheckDepsHandler{checker: checker}
}

type CheckDepsArgs struct {
	Path string `json:"path"`
}

func (h *CheckDepsHandler) Handle(ctx context.Context, args CheckDepsArgs) (string, error) {
	if args.Path == "" {
		return "", fmt.Errorf("path is required")
	}

	results, err := h.checker.Check(ctx, args.Path)
	if err != nil {
		return "", fmt.Errorf("dependency check failed: %w", err)
	}

	return formatCheckResults(results, args.Path), nil
}

func formatCheckResults(results []deps.CheckResult, path string) string {
	var sb strings.Builder

	sb.WriteString("## MCP-SCT Dependency Vulnerability Check\n\n")
	sb.WriteString(fmt.Sprintf("**Path:** `%s`\n\n", path))

	if len(results) == 0 {
		sb.WriteString("No dependency manifest files found (go.mod, package.json, requirements.txt).\n")
		return sb.String()
	}

	totalVulns := 0
	for _, r := range results {
		totalVulns += len(r.Vulnerabilities)
	}

	if totalVulns == 0 {
		sb.WriteString("No known vulnerabilities found in dependencies.\n\n")
		for _, r := range results {
			sb.WriteString(fmt.Sprintf("- `%s`: %d dependencies checked (%s)\n", r.Source, r.TotalDeps, r.Ecosystem))
		}
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("**Total vulnerabilities found:** %d\n\n", totalVulns))

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("### %s (`%s`)\n\n", r.Ecosystem, r.Source))
		sb.WriteString(fmt.Sprintf("Dependencies: %d | Vulnerable: %d\n\n", r.TotalDeps, r.VulnerableDeps))

		if len(r.Vulnerabilities) == 0 {
			sb.WriteString("No vulnerabilities found.\n\n")
			continue
		}

		// Summary by severity
		critical := r.CountBySeverity("CRITICAL")
		high := r.CountBySeverity("HIGH")
		medium := r.CountBySeverity("MEDIUM")
		low := r.CountBySeverity("LOW")

		sb.WriteString("| Severity | Count |\n|----------|-------|\n")
		if critical > 0 {
			sb.WriteString(fmt.Sprintf("| CRITICAL | %d |\n", critical))
		}
		if high > 0 {
			sb.WriteString(fmt.Sprintf("| HIGH | %d |\n", high))
		}
		if medium > 0 {
			sb.WriteString(fmt.Sprintf("| MEDIUM | %d |\n", medium))
		}
		if low > 0 {
			sb.WriteString(fmt.Sprintf("| LOW | %d |\n", low))
		}
		sb.WriteString("\n")

		// Detail each vulnerability
		for i, v := range r.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("**%d. %s** `%s@%s`\n", i+1, v.ID, v.Dependency.Name, v.Dependency.Version))
			sb.WriteString(fmt.Sprintf("   Severity: **%s**\n", v.Severity))

			if len(v.Aliases) > 0 {
				sb.WriteString(fmt.Sprintf("   Aliases: %s\n", strings.Join(v.Aliases, ", ")))
			}

			if v.Summary != "" {
				sb.WriteString(fmt.Sprintf("   %s\n", v.Summary))
			}

			if v.FixVersion != "" {
				sb.WriteString(fmt.Sprintf("   **Fix:** Upgrade to version `%s`\n", v.FixVersion))
			}

			if len(v.References) > 0 {
				sb.WriteString("   References:\n")
				for _, ref := range v.References {
					sb.WriteString(fmt.Sprintf("   - %s\n", ref))
				}
			}

			sb.WriteString("\n---\n\n")
		}
	}

	return sb.String()
}
