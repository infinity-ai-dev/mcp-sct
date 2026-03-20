package scanner

import (
	"context"
	"io/fs"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mcp-sct/mcp-sct/internal/rules"
	"github.com/mcp-sct/mcp-sct/internal/rules/builtin"
	"github.com/mcp-sct/mcp-sct/internal/types"
)

func setupTestEngine(t *testing.T) *Engine {
	t.Helper()

	registry := rules.NewRegistry()

	rulesFS, err := fs.Sub(builtin.RulesFS, "rules")
	if err != nil {
		t.Fatalf("Failed to access builtin rules: %v", err)
	}
	builtinRules, err := rules.LoadFromFS(rulesFS)
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}
	if err := registry.RegisterAll(builtinRules); err != nil {
		t.Fatalf("Failed to register rules: %v", err)
	}

	return NewEngine(registry, runtime.NumCPU(), 1*1024*1024, nil)
}

func projectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func TestScanVulnerablePython(t *testing.T) {
	engine := setupTestEngine(t)
	testFile := filepath.Join(projectRoot(), "testdata", "vulnerable.py")

	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:              testFile,
		SeverityThreshold: types.SeverityLow,
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.FilesScanned != 1 {
		t.Errorf("Expected 1 file scanned, got %d", result.FilesScanned)
	}

	if len(result.Findings) == 0 {
		t.Error("Expected findings in vulnerable.py, got 0")
	}

	// Should detect SQL injection
	hasSQLi := false
	for _, f := range result.Findings {
		if f.Category == "injection" && f.CWE == "CWE-89" {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Error("Expected SQL injection finding")
	}

	t.Logf("Found %d vulnerabilities in vulnerable.py", len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  [%s] %s at line %d (%s)", f.Severity, f.Category, f.StartLine, f.RuleID)
	}
}

func TestScanVulnerableJS(t *testing.T) {
	engine := setupTestEngine(t)
	testFile := filepath.Join(projectRoot(), "testdata", "vulnerable.js")

	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:              testFile,
		SeverityThreshold: types.SeverityLow,
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Error("Expected findings in vulnerable.js, got 0")
	}

	t.Logf("Found %d vulnerabilities in vulnerable.js", len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  [%s] %s at line %d (%s)", f.Severity, f.Category, f.StartLine, f.RuleID)
	}
}

func TestScanDirectory(t *testing.T) {
	engine := setupTestEngine(t)
	testDir := filepath.Join(projectRoot(), "testdata")

	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:              testDir,
		SeverityThreshold: types.SeverityLow,
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.FilesScanned < 2 {
		t.Errorf("Expected at least 2 files scanned, got %d", result.FilesScanned)
	}

	t.Logf("Scanned %d files, found %d total vulnerabilities", result.FilesScanned, len(result.Findings))
}

func TestScanSeverityFilter(t *testing.T) {
	engine := setupTestEngine(t)
	testFile := filepath.Join(projectRoot(), "testdata", "vulnerable.py")

	result, err := engine.Scan(context.Background(), ScanRequest{
		Path:              testFile,
		SeverityThreshold: types.SeverityCritical,
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.Severity < types.SeverityCritical {
			t.Errorf("Finding %s has severity %s, expected at least CRITICAL", f.RuleID, f.Severity)
		}
	}

	t.Logf("Found %d CRITICAL vulnerabilities", len(result.Findings))
}
