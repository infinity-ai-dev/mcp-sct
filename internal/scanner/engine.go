package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mcp-sct/mcp-sct/internal/rules"
	"github.com/mcp-sct/mcp-sct/internal/types"
)

// Engine orchestrates concurrent security scanning.
type Engine struct {
	registry        *rules.Registry
	workers         int
	maxFileSize     int64
	excludePatterns []string
	taintEngine     *TaintEngine
}

// NewEngine creates a scanning engine.
func NewEngine(registry *rules.Registry, workers int, maxFileSize int64, excludePatterns []string) *Engine {
	if workers <= 0 {
		workers = 4
	}
	if maxFileSize <= 0 {
		maxFileSize = 1 * 1024 * 1024
	}
	return &Engine{
		registry:        registry,
		workers:         workers,
		maxFileSize:     maxFileSize,
		excludePatterns: excludePatterns,
		taintEngine:     NewTaintEngine(),
	}
}

// ScanRequest defines what to scan.
type ScanRequest struct {
	Path              string
	Language          string
	SeverityThreshold types.Severity
	RuleIDs           []string
}

// Scan performs a concurrent security scan.
func (e *Engine) Scan(ctx context.Context, req ScanRequest) (*types.ScanResult, error) {
	files, err := e.discoverFiles(req.Path, req.Language)
	if err != nil {
		return nil, err
	}

	result := &types.ScanResult{
		Path:         req.Path,
		FilesScanned: len(files),
	}

	if len(files) == 0 {
		return result, nil
	}

	fileCh := make(chan string, len(files))
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	findingsCh := make(chan []types.Finding, len(files))
	var wg sync.WaitGroup

	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case file, ok := <-fileCh:
					if !ok {
						return
					}
					findings := e.scanFile(file, req)
					if len(findings) > 0 {
						findingsCh <- findings
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(findingsCh)
	}()

	for findings := range findingsCh {
		for _, f := range findings {
			if f.Severity >= req.SeverityThreshold {
				result.Findings = append(result.Findings, f)
			}
		}
	}

	sortFindings(result.Findings)

	return result, nil
}

func (e *Engine) scanFile(filePath string, req ScanRequest) []types.Finding {
	lang := DetectLanguage(filePath)
	if lang == "" {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	applicableRules := e.registry.ForLanguage(lang)
	if len(req.RuleIDs) > 0 {
		applicableRules = filterRules(applicableRules, req.RuleIDs)
	}

	var findings []types.Finding
	contentStr := string(content)

	// Phase 1: Rule-based pattern matching
	for _, rule := range applicableRules {
		matches := rules.Match(rule, filePath, contentStr)
		findings = append(findings, matches...)
	}

	// Phase 2: Taint analysis (source-to-sink data flow)
	taintFindings := e.taintEngine.Analyze(filePath, contentStr, lang)
	findings = append(findings, taintFindings...)

	return findings
}

func (e *Engine) discoverFiles(root string, langFilter string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if langFilter != "" && DetectLanguage(root) != langFilter {
			return nil, nil
		}
		if info.Size() <= e.maxFileSize && IsSourceFile(root) {
			return []string{root}, nil
		}
		return nil, nil
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if e.shouldExcludeDir(path, root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !IsSourceFile(path) {
			return nil
		}
		if langFilter != "" && DetectLanguage(path) != langFilter {
			return nil
		}
		if e.shouldExcludeFile(path, root) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > e.maxFileSize {
			return nil
		}
		files = append(files, path)
		return nil
	})

	return files, err
}

func (e *Engine) shouldExcludeDir(path, root string) bool {
	rel, _ := filepath.Rel(root, path)
	dirName := filepath.Base(path)

	if strings.HasPrefix(dirName, ".") {
		return true
	}

	for _, pattern := range e.excludePatterns {
		if matched, _ := filepath.Match(strings.TrimSuffix(pattern, "/**"), rel); matched {
			return true
		}
		if matched, _ := filepath.Match(strings.TrimSuffix(pattern, "/**"), dirName); matched {
			return true
		}
	}
	return false
}

func (e *Engine) shouldExcludeFile(path, root string) bool {
	rel, _ := filepath.Rel(root, path)
	baseName := filepath.Base(path)

	for _, pattern := range e.excludePatterns {
		if matched, _ := filepath.Match(pattern, rel); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, baseName); matched {
			return true
		}
	}
	return false
}

func filterRules(all []*rules.Rule, ids []string) []*rules.Rule {
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	var filtered []*rules.Rule
	for _, r := range all {
		if idSet[r.ID] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func sortFindings(findings []types.Finding) {
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if findings[j].Severity > findings[i].Severity {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}
