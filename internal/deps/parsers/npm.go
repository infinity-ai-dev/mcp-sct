package parsers

import (
	"encoding/json"
	"path/filepath"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// NPMParser parses package.json and package-lock.json files.
type NPMParser struct{}

func (p *NPMParser) CanParse(filename string) bool {
	base := filepath.Base(filename)
	return base == "package.json" || base == "package-lock.json"
}

func (p *NPMParser) Parse(content []byte, source string) ([]deps.Dependency, error) {
	base := filepath.Base(source)

	if base == "package-lock.json" {
		return p.parseLockfile(content, source)
	}
	return p.parsePackageJSON(content, source)
}

func (p *NPMParser) parsePackageJSON(content []byte, source string) ([]deps.Dependency, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, err
	}

	var result []deps.Dependency
	for name, version := range pkg.Dependencies {
		result = append(result, deps.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: "npm",
			Source:     source,
		})
	}
	for name, version := range pkg.DevDependencies {
		result = append(result, deps.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: "npm",
			Source:     source,
		})
	}

	return result, nil
}

type lockfileV3 struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

type lockfileV1 struct {
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func (p *NPMParser) parseLockfile(content []byte, source string) ([]deps.Dependency, error) {
	// Try v3 format first (npm 7+)
	var v3 lockfileV3
	if err := json.Unmarshal(content, &v3); err == nil && len(v3.Packages) > 0 {
		var result []deps.Dependency
		for path, pkg := range v3.Packages {
			if path == "" || pkg.Version == "" {
				continue
			}
			// Extract package name from path like "node_modules/express"
			name := path
			if idx := len("node_modules/"); len(path) > idx {
				name = path[idx:]
			}
			result = append(result, deps.Dependency{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				Source:     source,
			})
		}
		if len(result) > 0 {
			return result, nil
		}
	}

	// Fall back to v1 format
	var v1 lockfileV1
	if err := json.Unmarshal(content, &v1); err != nil {
		return nil, err
	}

	var result []deps.Dependency
	for name, dep := range v1.Dependencies {
		result = append(result, deps.Dependency{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
			Source:     source,
		})
	}

	return result, nil
}

func cleanNPMVersion(v string) string {
	// Remove semver range operators: ^, ~, >=, etc.
	v = trimLeftAny(v, "^~>=<")
	return v
}

func trimLeftAny(s string, chars string) string {
	for len(s) > 0 {
		found := false
		for _, c := range chars {
			if rune(s[0]) == c {
				s = s[1:]
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return s
}
