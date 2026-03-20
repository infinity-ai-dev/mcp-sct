package deps

// Dependency represents a single project dependency.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // "npm", "Go", "PyPI", "Maven"
	Source     string `json:"source"`    // lockfile path
}

// VulnMatch represents a known vulnerability matching a dependency.
type VulnMatch struct {
	ID          string     `json:"id"`          // e.g., "GHSA-xxxx" or "CVE-2024-xxxx"
	Aliases     []string   `json:"aliases"`     // alternate IDs
	Summary     string     `json:"summary"`
	Details     string     `json:"details"`
	Severity    string     `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW
	FixVersion  string     `json:"fix_version"` // version that fixes the vuln
	References  []string   `json:"references"`
	Dependency  Dependency `json:"dependency"`
}

// CheckResult holds the results of a dependency vulnerability check.
type CheckResult struct {
	Source           string       `json:"source"` // lockfile path
	Ecosystem        string       `json:"ecosystem"`
	TotalDeps        int          `json:"total_deps"`
	VulnerableDeps   int          `json:"vulnerable_deps"`
	Vulnerabilities  []VulnMatch  `json:"vulnerabilities"`
}

func (r *CheckResult) CountBySeverity(sev string) int {
	count := 0
	for _, v := range r.Vulnerabilities {
		if v.Severity == sev {
			count++
		}
	}
	return count
}
