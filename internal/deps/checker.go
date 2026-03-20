package deps

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Parser extracts dependencies from lockfiles.
type Parser interface {
	CanParse(filename string) bool
	Parse(content []byte, source string) ([]Dependency, error)
}

// VulnSource queries vulnerability databases.
type VulnSource interface {
	Name() string
	Query(ctx context.Context, deps []Dependency) ([]VulnMatch, error)
}

// Checker coordinates dependency parsing and vulnerability checking.
type Checker struct {
	parsers []Parser
	sources []VulnSource
}

// NewChecker creates a dependency checker with the given parsers and vulnerability sources.
func NewChecker(parsers []Parser, sources []VulnSource) *Checker {
	return &Checker{
		parsers: parsers,
		sources: sources,
	}
}

// lockfileNames lists known dependency manifest filenames.
var lockfileNames = map[string]bool{
	"go.mod":              true,
	"package.json":        true,
	"package-lock.json":   true,
	"requirements.txt":    true,
	"requirements-dev.txt": true,
	"pom.xml":             true,
	"Cargo.lock":          true,
	"composer.lock":       true,
}

// Check scans a path for lockfiles and checks dependencies against vulnerability databases.
func (c *Checker) Check(ctx context.Context, path string) ([]CheckResult, error) {
	lockfiles, err := c.findLockfiles(path)
	if err != nil {
		return nil, fmt.Errorf("finding lockfiles: %w", err)
	}

	if len(lockfiles) == 0 {
		return nil, nil
	}

	var results []CheckResult

	for _, lf := range lockfiles {
		content, err := os.ReadFile(lf)
		if err != nil {
			continue
		}

		for _, parser := range c.parsers {
			if !parser.CanParse(lf) {
				continue
			}

			dependencies, err := parser.Parse(content, lf)
			if err != nil {
				continue
			}

			if len(dependencies) == 0 {
				continue
			}

			result := CheckResult{
				Source:    lf,
				Ecosystem: dependencies[0].Ecosystem,
				TotalDeps: len(dependencies),
			}

			// Query all vulnerability sources
			for _, source := range c.sources {
				vulns, err := source.Query(ctx, dependencies)
				if err != nil {
					// Log but continue with other sources
					continue
				}
				result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			}

			// Count unique vulnerable deps
			vulnDeps := make(map[string]bool)
			for _, v := range result.Vulnerabilities {
				vulnDeps[v.Dependency.Name] = true
			}
			result.VulnerableDeps = len(vulnDeps)

			results = append(results, result)
			break // only use first matching parser per file
		}
	}

	return results, nil
}

func (c *Checker) findLockfiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Single file
	if !info.IsDir() {
		base := filepath.Base(path)
		if lockfileNames[base] || strings.HasPrefix(base, "requirements") {
			return []string{path}, nil
		}
		return nil, nil
	}

	// Directory - search up to 3 levels deep
	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Skip deep directories and common non-relevant dirs
			rel, _ := filepath.Rel(path, p)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth > 2 {
				return filepath.SkipDir
			}
			base := filepath.Base(p)
			if base == "node_modules" || base == ".git" || base == "vendor" || base == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(p)
		if lockfileNames[base] || (strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")) {
			files = append(files, p)
		}
		return nil
	})

	return files, err
}
