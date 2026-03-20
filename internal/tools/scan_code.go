package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/scanner"
	"github.com/mcp-sct/mcp-sct/internal/types"
)

type ScanCodeHandler struct {
	engine *scanner.Engine
}

func NewScanCodeHandler(engine *scanner.Engine) *ScanCodeHandler {
	return &ScanCodeHandler{engine: engine}
}

type ScanCodeArgs struct {
	Path              string   `json:"path"`
	Language          string   `json:"language,omitempty"`
	SeverityThreshold string   `json:"severity_threshold,omitempty"`
	RuleIDs           []string `json:"rule_ids,omitempty"`
}

func (h *ScanCodeHandler) Handle(ctx context.Context, args ScanCodeArgs) (string, error) {
	if args.Path == "" {
		return "", fmt.Errorf("path is required")
	}

	threshold := types.SeverityLow
	if args.SeverityThreshold != "" {
		threshold = types.ParseSeverity(args.SeverityThreshold)
	}

	result, err := h.engine.Scan(ctx, scanner.ScanRequest{
		Path:              args.Path,
		Language:          args.Language,
		SeverityThreshold: threshold,
		RuleIDs:           args.RuleIDs,
	})
	if err != nil {
		return "", fmt.Errorf("scan failed: %w", err)
	}

	return formatScanResult(result), nil
}

func formatScanResult(result *types.ScanResult) string {
	var sb strings.Builder

	sb.WriteString("## MCP-SCT Security Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("**Path:** `%s`\n", result.Path))
	sb.WriteString(fmt.Sprintf("**Files scanned:** %d\n", result.FilesScanned))
	sb.WriteString(fmt.Sprintf("**Vulnerabilities found:** %d\n\n", len(result.Findings)))

	if len(result.Findings) == 0 {
		sb.WriteString("No security vulnerabilities detected.\n")
		return sb.String()
	}

	critical := result.CountBySeverity(types.SeverityCritical)
	high := result.CountBySeverity(types.SeverityHigh)
	medium := result.CountBySeverity(types.SeverityMedium)
	low := result.CountBySeverity(types.SeverityLow)

	sb.WriteString("### Summary\n")
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

	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
	}

	for _, sev := range severities {
		findings := filterBySeverity(result.Findings, sev)
		if len(findings) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("### %s (%d)\n\n", sev.String(), len(findings)))

		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("**%d. %s** [%s] [%s]\n", i+1, f.Category, f.CWE, f.OWASP))
			sb.WriteString(fmt.Sprintf("   File: `%s:%d`\n", f.FilePath, f.StartLine))
			sb.WriteString(fmt.Sprintf("   Rule: `%s`\n", f.RuleID))
			sb.WriteString(fmt.Sprintf("   %s\n", strings.TrimSpace(f.Message)))

			if f.Snippet != "" {
				sb.WriteString(fmt.Sprintf("\n   ```\n%s\n   ```\n", indentSnippet(f.Snippet)))
			}

			if f.FixHint != "" {
				sb.WriteString(fmt.Sprintf("\n   **Fix:**\n%s\n", indentBlock(f.FixHint)))
			}
			sb.WriteString("\n---\n\n")
		}
	}

	return sb.String()
}

func filterBySeverity(findings []types.Finding, sev types.Severity) []types.Finding {
	var result []types.Finding
	for _, f := range findings {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

func indentSnippet(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "   " + line
	}
	return strings.Join(lines, "\n")
}

func indentBlock(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, line := range lines {
		lines[i] = "   " + line
	}
	return strings.Join(lines, "\n")
}
