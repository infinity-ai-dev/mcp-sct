package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/bridge"
)

// SuggestFixesHandler handles the suggest_fixes tool.
type SuggestFixesHandler struct {
	manager *bridge.Manager
}

func NewSuggestFixesHandler(manager *bridge.Manager) *SuggestFixesHandler {
	return &SuggestFixesHandler{manager: manager}
}

type SuggestFixesArgs struct {
	Code              string `json:"code"`
	Language          string `json:"language"`
	FilePath          string `json:"file_path,omitempty"`
	VulnerabilityType string `json:"vulnerability_type,omitempty"`
	RuleID            string `json:"rule_id,omitempty"`
	FindingMessage    string `json:"finding_message,omitempty"`
	StartLine         int    `json:"start_line,omitempty"`
	EndLine           int    `json:"end_line,omitempty"`
}

func (h *SuggestFixesHandler) Handle(ctx context.Context, args SuggestFixesArgs) (string, error) {
	if args.Code == "" {
		return "", fmt.Errorf("code is required")
	}
	if args.Language == "" {
		return "", fmt.Errorf("language is required")
	}

	// Check if AI bridge is available
	if h.manager == nil || !h.manager.IsAvailable() {
		return h.fallbackResponse(args), nil
	}

	// Call AI bridge
	req := &bridge.AnalyzeRequest{
		Code:              args.Code,
		Language:          args.Language,
		FilePath:          args.FilePath,
		VulnerabilityType: args.VulnerabilityType,
		RuleID:            args.RuleID,
		FindingMessage:    args.FindingMessage,
		StartLine:         args.StartLine,
		EndLine:           args.EndLine,
	}

	resp, err := h.manager.Client().SuggestFix(ctx, req)
	if err != nil {
		// Graceful degradation: return fallback on error
		return h.fallbackResponse(args), nil
	}

	if resp.Error != "" {
		return h.fallbackResponse(args), nil
	}

	return formatAIResponse(resp, args), nil
}

func formatAIResponse(resp *bridge.AnalyzeResponse, args SuggestFixesArgs) string {
	var sb strings.Builder

	sb.WriteString("## MCP-SCT AI Security Fix Suggestion\n\n")
	sb.WriteString(fmt.Sprintf("**Model:** %s\n", resp.ModelUsed))
	sb.WriteString(fmt.Sprintf("**Language:** %s\n", args.Language))

	if args.VulnerabilityType != "" {
		sb.WriteString(fmt.Sprintf("**Vulnerability:** %s\n", args.VulnerabilityType))
	}
	if args.RuleID != "" {
		sb.WriteString(fmt.Sprintf("**Rule:** %s\n", args.RuleID))
	}
	sb.WriteString("\n")

	for i, s := range resp.Suggestions {
		if len(resp.Suggestions) > 1 {
			sb.WriteString(fmt.Sprintf("### Suggestion %d (confidence: %.0f%%)\n\n", i+1, s.Confidence*100))
		}

		if s.Explanation != "" {
			sb.WriteString("### Explanation\n")
			sb.WriteString(s.Explanation)
			sb.WriteString("\n\n")
		}

		if s.FixedCode != "" {
			sb.WriteString("### Fixed Code\n")
			sb.WriteString(fmt.Sprintf("```%s\n%s\n```\n\n", args.Language, s.FixedCode))
		}

		if len(s.References) > 0 {
			sb.WriteString("### References\n")
			for _, ref := range s.References {
				sb.WriteString(fmt.Sprintf("- %s\n", ref))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (h *SuggestFixesHandler) fallbackResponse(args SuggestFixesArgs) string {
	var sb strings.Builder

	sb.WriteString("## MCP-SCT Security Fix Suggestion (Rule-based)\n\n")
	sb.WriteString("*AI bridge not available. Showing deterministic suggestions.*\n")
	sb.WriteString("*Configure an AI provider (Ollama, OpenAI, or Anthropic) for intelligent fixes.*\n\n")

	sb.WriteString(fmt.Sprintf("**Language:** %s\n", args.Language))
	if args.VulnerabilityType != "" {
		sb.WriteString(fmt.Sprintf("**Vulnerability:** %s\n\n", args.VulnerabilityType))
	}

	// Provide general fix advice based on vulnerability type
	vulnType := strings.ToLower(args.VulnerabilityType)
	switch {
	case strings.Contains(vulnType, "sql") || strings.Contains(vulnType, "injection"):
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Use parameterized queries instead of string concatenation/formatting.\n")
		sb.WriteString("Never embed user input directly into SQL strings.\n\n")

	case strings.Contains(vulnType, "xss") || strings.Contains(vulnType, "cross-site scripting"):
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Escape all user-provided data before rendering in HTML.\n")
		sb.WriteString("Use framework auto-escaping and Content-Security-Policy headers.\n\n")

	case strings.Contains(vulnType, "command"):
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Pass arguments as arrays, not concatenated strings.\n")
		sb.WriteString("Avoid shell=True and eval() with user input.\n\n")

	case strings.Contains(vulnType, "secret") || strings.Contains(vulnType, "credential"):
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Use environment variables or a secrets manager.\n")
		sb.WriteString("Never hardcode credentials in source code.\n\n")

	case strings.Contains(vulnType, "deserial"):
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Use safe deserialization (JSON, yaml.safe_load).\n")
		sb.WriteString("Never deserialize untrusted data with pickle or native serialization.\n\n")

	case strings.Contains(vulnType, "path") || strings.Contains(vulnType, "traversal"):
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Validate and canonicalize file paths.\n")
		sb.WriteString("Verify the resolved path stays within the allowed directory.\n\n")

	default:
		sb.WriteString("### Recommendation\n")
		sb.WriteString("Review the code for the identified vulnerability.\n")
		sb.WriteString("Consult OWASP guidelines for the specific vulnerability type.\n")
		sb.WriteString("Use `get_security_guidelines` for detailed best practices.\n\n")
	}

	if args.FindingMessage != "" {
		sb.WriteString("### Original Finding\n")
		sb.WriteString(args.FindingMessage)
		sb.WriteString("\n")
	}

	return sb.String()
}
