package parsers

import (
	"bufio"
	"path/filepath"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// CargoParser parses Cargo.lock files (Rust).
type CargoParser struct{}

func (p *CargoParser) CanParse(filename string) bool {
	return filepath.Base(filename) == "Cargo.lock"
}

func (p *CargoParser) Parse(content []byte, source string) ([]deps.Dependency, error) {
	var result []deps.Dependency
	scanner := bufio.NewScanner(strings.NewReader(string(content)))

	var currentName, currentVersion string
	inPackage := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			// Save previous package
			if currentName != "" && currentVersion != "" {
				result = append(result, deps.Dependency{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: "crates.io",
					Source:     source,
				})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
	}

	// Save last package
	if currentName != "" && currentVersion != "" {
		result = append(result, deps.Dependency{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: "crates.io",
			Source:     source,
		})
	}

	return result, scanner.Err()
}
