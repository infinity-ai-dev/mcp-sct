package types

import "strings"

// Severity levels for security findings.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func ParseSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "INFO":
		return SeverityInfo
	case "LOW":
		return SeverityLow
	case "MEDIUM":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// Finding represents a single security vulnerability detected in code.
type Finding struct {
	RuleID     string   `json:"rule_id"`
	Severity   Severity `json:"severity"`
	Category   string   `json:"category"`
	Message    string   `json:"message"`
	FilePath   string   `json:"file_path"`
	StartLine  int      `json:"start_line"`
	EndLine    int      `json:"end_line"`
	Snippet    string   `json:"snippet"`
	CWE        string   `json:"cwe"`
	OWASP      string   `json:"owasp"`
	FixHint    string   `json:"fix_hint"`
	Confidence float64  `json:"confidence"`
	References []string `json:"references,omitempty"`
}

// ScanResult holds the aggregated results of a security scan.
type ScanResult struct {
	Path         string    `json:"path"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
}

func (r *ScanResult) CountBySeverity(sev Severity) int {
	count := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}
