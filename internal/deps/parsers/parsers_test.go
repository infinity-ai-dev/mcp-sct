package parsers

import (
	"testing"
)

func TestGoModParser(t *testing.T) {
	content := []byte(`module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/lib/pq v1.10.9
	golang.org/x/crypto v0.14.0 // indirect
)
`)

	parser := &GoModParser{}

	if !parser.CanParse("go.mod") {
		t.Fatal("GoModParser should parse go.mod")
	}
	if parser.CanParse("package.json") {
		t.Fatal("GoModParser should not parse package.json")
	}

	deps, err := parser.Parse(content, "go.mod")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 deps, got %d", len(deps))
	}

	if deps[0].Name != "github.com/gin-gonic/gin" {
		t.Errorf("Expected gin, got %s", deps[0].Name)
	}
	if deps[0].Version != "1.9.1" {
		t.Errorf("Expected 1.9.1, got %s", deps[0].Version)
	}
	if deps[0].Ecosystem != "Go" {
		t.Errorf("Expected Go ecosystem, got %s", deps[0].Ecosystem)
	}
}

func TestNPMParser_PackageJSON(t *testing.T) {
	content := []byte(`{
  "name": "myapp",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`)

	parser := &NPMParser{}

	if !parser.CanParse("package.json") {
		t.Fatal("NPMParser should parse package.json")
	}

	deps, err := parser.Parse(content, "package.json")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 deps, got %d", len(deps))
	}

	// Check version cleaning
	for _, d := range deps {
		if d.Ecosystem != "npm" {
			t.Errorf("Expected npm ecosystem, got %s", d.Ecosystem)
		}
		if d.Name == "express" && d.Version != "4.18.2" {
			t.Errorf("Expected clean version 4.18.2, got %s", d.Version)
		}
	}
}

func TestPipParser(t *testing.T) {
	content := []byte(`# Production deps
Flask==2.3.3
requests>=2.31.0,<3.0
SQLAlchemy[asyncio]~=2.0.21
gunicorn==21.2.0

# Dev deps
-e .
pytest>=7.0
# Comment line
`)

	parser := &PipParser{}

	if !parser.CanParse("requirements.txt") {
		t.Fatal("PipParser should parse requirements.txt")
	}

	deps, err := parser.Parse(content, "requirements.txt")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 5 {
		t.Fatalf("Expected 5 deps, got %d", len(deps))
	}

	for _, d := range deps {
		if d.Ecosystem != "PyPI" {
			t.Errorf("Expected PyPI ecosystem, got %s", d.Ecosystem)
		}
	}

	// Check Flask
	if deps[0].Name != "Flask" || deps[0].Version != "2.3.3" {
		t.Errorf("Expected Flask==2.3.3, got %s==%s", deps[0].Name, deps[0].Version)
	}

	// Check requests with range
	if deps[1].Name != "requests" || deps[1].Version != "2.31.0" {
		t.Errorf("Expected requests>=2.31.0, got %s>=%s", deps[1].Name, deps[1].Version)
	}

	// Check SQLAlchemy with extras
	if deps[2].Name != "SQLAlchemy" {
		t.Errorf("Expected SQLAlchemy, got %s", deps[2].Name)
	}
}
