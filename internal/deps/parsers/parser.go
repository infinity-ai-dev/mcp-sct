package parsers

import "github.com/mcp-sct/mcp-sct/internal/deps"

// DependencyParser extracts dependencies from lockfiles.
type DependencyParser interface {
	// CanParse returns true if the parser handles this file.
	CanParse(filename string) bool
	// Parse extracts dependencies from file content.
	Parse(content []byte, source string) ([]deps.Dependency, error)
}

// All returns all available parsers.
func All() []DependencyParser {
	return []DependencyParser{
		&GoModParser{},
		&NPMParser{},
		&PipParser{},
		&MavenParser{},
		&CargoParser{},
		&ComposerParser{},
	}
}
