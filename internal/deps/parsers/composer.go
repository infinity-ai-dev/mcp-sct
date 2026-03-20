package parsers

import (
	"encoding/json"
	"path/filepath"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// ComposerParser parses composer.lock files (PHP).
type ComposerParser struct{}

func (p *ComposerParser) CanParse(filename string) bool {
	return filepath.Base(filename) == "composer.lock"
}

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (p *ComposerParser) Parse(content []byte, source string) ([]deps.Dependency, error) {
	var lock composerLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	var result []deps.Dependency
	for _, pkg := range lock.Packages {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		v := pkg.Version
		if len(v) > 0 && v[0] == 'v' {
			v = v[1:]
		}
		result = append(result, deps.Dependency{
			Name:      pkg.Name,
			Version:   v,
			Ecosystem: "Packagist",
			Source:     source,
		})
	}
	for _, pkg := range lock.PackagesDev {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		v := pkg.Version
		if len(v) > 0 && v[0] == 'v' {
			v = v[1:]
		}
		result = append(result, deps.Dependency{
			Name:      pkg.Name,
			Version:   v,
			Ecosystem: "Packagist",
			Source:     source,
		})
	}

	return result, nil
}
