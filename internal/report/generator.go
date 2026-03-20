package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mcp-sct/mcp-sct/internal/deps"
	"github.com/mcp-sct/mcp-sct/internal/types"
)

// FullReport consolidates all security analysis results.
type FullReport struct {
	Timestamp    time.Time          `json:"timestamp"`
	Path         string             `json:"path"`
	Format       string             `json:"format"`
	ScanResult   *types.ScanResult  `json:"scan_result,omitempty"`
	DepsResults  []deps.CheckResult `json:"deps_results,omitempty"`
	Summary      ReportSummary      `json:"summary"`
}

type ReportSummary struct {
	FilesScanned      int `json:"files_scanned"`
	TotalFindings     int `json:"total_findings"`
	CriticalCount     int `json:"critical_count"`
	HighCount         int `json:"high_count"`
	MediumCount       int `json:"medium_count"`
	LowCount          int `json:"low_count"`
	DepsChecked       int `json:"deps_checked"`
	VulnerableDeps    int `json:"vulnerable_deps"`
	DepsVulnCount     int `json:"deps_vuln_count"`
}

func NewFullReport(path string, scan *types.ScanResult, depsResults []deps.CheckResult) *FullReport {
	r := &FullReport{
		Timestamp:   time.Now(),
		Path:        path,
		ScanResult:  scan,
		DepsResults: depsResults,
	}
	r.buildSummary()
	return r
}

func (r *FullReport) buildSummary() {
	if r.ScanResult != nil {
		r.Summary.FilesScanned = r.ScanResult.FilesScanned
		r.Summary.TotalFindings = len(r.ScanResult.Findings)
		r.Summary.CriticalCount = r.ScanResult.CountBySeverity(types.SeverityCritical)
		r.Summary.HighCount = r.ScanResult.CountBySeverity(types.SeverityHigh)
		r.Summary.MediumCount = r.ScanResult.CountBySeverity(types.SeverityMedium)
		r.Summary.LowCount = r.ScanResult.CountBySeverity(types.SeverityLow)
	}
	for _, dr := range r.DepsResults {
		r.Summary.DepsChecked += dr.TotalDeps
		r.Summary.VulnerableDeps += dr.VulnerableDeps
		r.Summary.DepsVulnCount += len(dr.Vulnerabilities)
	}
}

// Render generates the report in the specified format.
func (r *FullReport) Render(format string) (string, error) {
	r.Format = format
	switch strings.ToLower(format) {
	case "markdown", "md", "":
		return r.renderMarkdown(), nil
	case "json":
		return r.renderJSON()
	case "sarif":
		return r.renderSARIF()
	default:
		return "", fmt.Errorf("unsupported format: %s (use: markdown, json, sarif)", format)
	}
}

func (r *FullReport) renderMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# MCP-SCT Security Report\n\n")
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", r.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Path:** `%s`\n\n", r.Path))

	// Executive summary
	sb.WriteString("## Executive Summary\n\n")
	total := r.Summary.TotalFindings + r.Summary.DepsVulnCount
	if total == 0 {
		sb.WriteString("No security issues found.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("**Total issues found: %d**\n\n", total))
		sb.WriteString("| Category | Count |\n|----------|-------|\n")
		if r.Summary.CriticalCount > 0 {
			sb.WriteString(fmt.Sprintf("| Code - CRITICAL | %d |\n", r.Summary.CriticalCount))
		}
		if r.Summary.HighCount > 0 {
			sb.WriteString(fmt.Sprintf("| Code - HIGH | %d |\n", r.Summary.HighCount))
		}
		if r.Summary.MediumCount > 0 {
			sb.WriteString(fmt.Sprintf("| Code - MEDIUM | %d |\n", r.Summary.MediumCount))
		}
		if r.Summary.LowCount > 0 {
			sb.WriteString(fmt.Sprintf("| Code - LOW | %d |\n", r.Summary.LowCount))
		}
		if r.Summary.DepsVulnCount > 0 {
			sb.WriteString(fmt.Sprintf("| Dependencies | %d |\n", r.Summary.DepsVulnCount))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("**Files scanned:** %d\n", r.Summary.FilesScanned))
	sb.WriteString(fmt.Sprintf("**Dependencies checked:** %d\n\n", r.Summary.DepsChecked))

	// Code findings
	if r.ScanResult != nil && len(r.ScanResult.Findings) > 0 {
		sb.WriteString("## Code Vulnerabilities\n\n")
		for i, f := range r.ScanResult.Findings {
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, f.Severity.String(), f.Category))
			sb.WriteString(fmt.Sprintf("- **File:** `%s:%d`\n", f.FilePath, f.StartLine))
			sb.WriteString(fmt.Sprintf("- **Rule:** `%s`\n", f.RuleID))
			sb.WriteString(fmt.Sprintf("- **CWE:** %s | **OWASP:** %s\n", f.CWE, f.OWASP))
			sb.WriteString(fmt.Sprintf("- %s\n", strings.TrimSpace(f.Message)))
			if f.Snippet != "" {
				sb.WriteString(fmt.Sprintf("\n```\n%s\n```\n", f.Snippet))
			}
			if f.FixHint != "" {
				sb.WriteString(fmt.Sprintf("\n**Recommended fix:**\n%s\n", f.FixHint))
			}
			sb.WriteString("\n---\n\n")
		}
	}

	// Dependency vulnerabilities
	if len(r.DepsResults) > 0 {
		hasVulns := false
		for _, dr := range r.DepsResults {
			if len(dr.Vulnerabilities) > 0 {
				hasVulns = true
				break
			}
		}
		if hasVulns {
			sb.WriteString("## Dependency Vulnerabilities\n\n")
			for _, dr := range r.DepsResults {
				if len(dr.Vulnerabilities) == 0 {
					continue
				}
				sb.WriteString(fmt.Sprintf("### %s (`%s`)\n\n", dr.Ecosystem, dr.Source))
				for _, v := range dr.Vulnerabilities {
					sb.WriteString(fmt.Sprintf("- **%s** `%s@%s` [%s]", v.ID, v.Dependency.Name, v.Dependency.Version, v.Severity))
					if v.FixVersion != "" {
						sb.WriteString(fmt.Sprintf(" -> upgrade to `%s`", v.FixVersion))
					}
					sb.WriteString("\n")
					if v.Summary != "" {
						sb.WriteString(fmt.Sprintf("  %s\n", v.Summary))
					}
				}
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString("---\n*Generated by MCP-SCT v0.3.0*\n")
	return sb.String()
}

func (r *FullReport) renderJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SARIF format for CI/CD integration (GitHub Code Scanning, GitLab SAST, etc.)
func (r *FullReport) renderSARIF() (string, error) {
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":            "MCP-SCT",
						"version":         "0.3.0",
						"informationUri":  "https://github.com/mcp-sct/mcp-sct",
						"rules":           r.buildSARIFRules(),
					},
				},
				"results": r.buildSARIFResults(),
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *FullReport) buildSARIFRules() []interface{} {
	seen := make(map[string]bool)
	var rules []interface{}

	if r.ScanResult == nil {
		return rules
	}

	for _, f := range r.ScanResult.Findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true

		level := "warning"
		switch f.Severity {
		case types.SeverityCritical:
			level = "error"
		case types.SeverityHigh:
			level = "error"
		case types.SeverityMedium:
			level = "warning"
		case types.SeverityLow:
			level = "note"
		}

		rule := map[string]interface{}{
			"id":   f.RuleID,
			"name": f.Category,
			"shortDescription": map[string]string{
				"text": strings.TrimSpace(f.Message),
			},
			"defaultConfiguration": map[string]string{
				"level": level,
			},
			"properties": map[string]interface{}{
				"tags": []string{f.Category, f.CWE, f.OWASP},
			},
		}
		rules = append(rules, rule)
	}
	return rules
}

func (r *FullReport) buildSARIFResults() []interface{} {
	var results []interface{}

	if r.ScanResult == nil {
		return results
	}

	for _, f := range r.ScanResult.Findings {
		level := "warning"
		switch f.Severity {
		case types.SeverityCritical, types.SeverityHigh:
			level = "error"
		case types.SeverityMedium:
			level = "warning"
		case types.SeverityLow:
			level = "note"
		}

		result := map[string]interface{}{
			"ruleId":  f.RuleID,
			"level":   level,
			"message": map[string]string{"text": strings.TrimSpace(f.Message)},
			"locations": []interface{}{
				map[string]interface{}{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": f.FilePath,
						},
						"region": map[string]interface{}{
							"startLine": f.StartLine,
							"endLine":   f.EndLine,
						},
					},
				},
			},
		}

		if f.FixHint != "" {
			result["fixes"] = []interface{}{
				map[string]interface{}{
					"description": map[string]string{"text": f.FixHint},
				},
			}
		}

		results = append(results, result)
	}

	return results
}
