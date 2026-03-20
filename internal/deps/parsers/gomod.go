package parsers

import (
	"bufio"
	"path/filepath"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// GoModParser parses go.mod files.
type GoModParser struct{}

func (p *GoModParser) CanParse(filename string) bool {
	return filepath.Base(filename) == "go.mod"
}

func (p *GoModParser) Parse(content []byte, source string) ([]deps.Dependency, error) {
	var result []deps.Dependency
	scanner := bufio.NewScanner(strings.NewReader(string(content)))

	inRequire := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			dep := parseGoRequireLine(strings.TrimPrefix(line, "require "))
			if dep != nil {
				dep.Source = source
				result = append(result, *dep)
			}
			continue
		}

		// Block require
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}

		if inRequire {
			dep := parseGoRequireLine(line)
			if dep != nil {
				dep.Source = source
				result = append(result, *dep)
			}
		}
	}

	return result, scanner.Err()
}

func parseGoRequireLine(line string) *deps.Dependency {
	line = strings.TrimSpace(line)
	// Remove // indirect comments
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	return &deps.Dependency{
		Name:      parts[0],
		Version:   strings.TrimPrefix(parts[1], "v"),
		Ecosystem: "Go",
	}
}
