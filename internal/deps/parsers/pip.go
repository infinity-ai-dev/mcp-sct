package parsers

import (
	"bufio"
	"path/filepath"
	"strings"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// PipParser parses requirements.txt files.
type PipParser struct{}

func (p *PipParser) CanParse(filename string) bool {
	base := filepath.Base(filename)
	return base == "requirements.txt" || base == "requirements-dev.txt" ||
		base == "requirements.lock" || strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

func (p *PipParser) Parse(content []byte, source string) ([]deps.Dependency, error) {
	var result []deps.Dependency
	scanner := bufio.NewScanner(strings.NewReader(string(content)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, options
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Remove environment markers: ; python_version >= "3.6"
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Remove extras: package[extra1,extra2]
		name := line
		if idx := strings.Index(name, "["); idx >= 0 {
			rest := name[idx:]
			closeIdx := strings.Index(rest, "]")
			if closeIdx >= 0 {
				name = name[:idx] + name[idx+closeIdx+1:]
			}
		}

		// Parse version specifiers
		var pkgName, version string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(name, sep); idx >= 0 {
				pkgName = strings.TrimSpace(name[:idx])
				version = strings.TrimSpace(name[idx+len(sep):])
				// Handle multiple version specs: pkg>=1.0,<2.0
				if commaIdx := strings.Index(version, ","); commaIdx >= 0 {
					version = version[:commaIdx]
				}
				break
			}
		}

		if pkgName == "" {
			pkgName = strings.TrimSpace(name)
		}

		if pkgName == "" {
			continue
		}

		result = append(result, deps.Dependency{
			Name:      pkgName,
			Version:   version,
			Ecosystem: "PyPI",
			Source:     source,
		})
	}

	return result, scanner.Err()
}
