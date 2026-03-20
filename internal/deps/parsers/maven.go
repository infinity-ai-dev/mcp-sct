package parsers

import (
	"encoding/xml"
	"path/filepath"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

// MavenParser parses pom.xml files.
type MavenParser struct{}

func (p *MavenParser) CanParse(filename string) bool {
	return filepath.Base(filename) == "pom.xml"
}

type pomProject struct {
	Dependencies struct {
		Dependency []pomDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

func (p *MavenParser) Parse(content []byte, source string) ([]deps.Dependency, error) {
	var pom pomProject
	if err := xml.Unmarshal(content, &pom); err != nil {
		return nil, err
	}

	var result []deps.Dependency
	seen := make(map[string]bool)

	for _, d := range pom.Dependencies.Dependency {
		key := d.GroupID + ":" + d.ArtifactID
		if seen[key] || d.Version == "" || d.Version[0] == '$' {
			continue
		}
		seen[key] = true
		result = append(result, deps.Dependency{
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   d.Version,
			Ecosystem: "Maven",
			Source:     source,
		})
	}

	for _, d := range pom.DependencyManagement.Dependencies.Dependency {
		key := d.GroupID + ":" + d.ArtifactID
		if seen[key] || d.Version == "" || d.Version[0] == '$' {
			continue
		}
		seen[key] = true
		result = append(result, deps.Dependency{
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   d.Version,
			Ecosystem: "Maven",
			Source:     source,
		})
	}

	return result, nil
}
