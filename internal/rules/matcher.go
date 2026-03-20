package rules

import (
	"fmt"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/types"
)

// Match checks a file's content against a rule and returns findings.
func Match(rule *Rule, filePath string, content string) []types.Finding {
	lines := strings.Split(content, "\n")
	var findings []types.Finding

	for _, re := range rule.CompiledPatterns() {
		matches := re.FindAllStringIndex(content, -1)
		for _, match := range matches {
			// Check if excluded
			if isExcluded(rule, content, match) {
				continue
			}

			startLine := lineNumber(content, match[0])
			endLine := lineNumber(content, match[1])
			snippet := extractSnippet(lines, startLine, 2)

			findings = append(findings, types.Finding{
				RuleID:     rule.ID,
				Severity:   types.ParseSeverity(rule.Severity),
				Category:   rule.Category,
				Message:    rule.Message,
				FilePath:   filePath,
				StartLine:  startLine,
				EndLine:    endLine,
				Snippet:    snippet,
				CWE:        rule.CWE,
				OWASP:      rule.OWASP,
				FixHint:    rule.FixTemplate,
				Confidence: rule.Confidence,
				References: rule.References,
			})
		}
	}

	return dedup(findings)
}

func isExcluded(rule *Rule, content string, matchLoc []int) bool {
	lineStart := strings.LastIndex(content[:matchLoc[0]], "\n") + 1
	lineEnd := strings.Index(content[matchLoc[0]:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += matchLoc[0]
	}
	line := content[lineStart:lineEnd]

	for _, re := range rule.CompiledExcludePatterns() {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func lineNumber(content string, offset int) int {
	return strings.Count(content[:offset], "\n") + 1
}

func extractSnippet(lines []string, targetLine int, context int) string {
	start := targetLine - context - 1
	if start < 0 {
		start = 0
	}
	end := targetLine + context
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// dedup removes findings that overlap on the same line for the same rule.
func dedup(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	result := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.StartLine)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}
