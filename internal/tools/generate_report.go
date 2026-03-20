package tools

import (
	"context"
	"fmt"

	"github.com/mcp-sct/mcp-sct/internal/deps"
	"github.com/mcp-sct/mcp-sct/internal/report"
	"github.com/mcp-sct/mcp-sct/internal/scanner"
	"github.com/mcp-sct/mcp-sct/internal/types"
)

// GenerateReportHandler handles the generate_report tool.
type GenerateReportHandler struct {
	engine  *scanner.Engine
	checker *deps.Checker
}

func NewGenerateReportHandler(engine *scanner.Engine, checker *deps.Checker) *GenerateReportHandler {
	return &GenerateReportHandler{engine: engine, checker: checker}
}

type GenerateReportArgs struct {
	Path   string `json:"path"`
	Format string `json:"format,omitempty"` // markdown, json, sarif
}

func (h *GenerateReportHandler) Handle(ctx context.Context, args GenerateReportArgs) (string, error) {
	if args.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	if args.Format == "" {
		args.Format = "markdown"
	}

	// Run code scan
	scanResult, err := h.engine.Scan(ctx, scanner.ScanRequest{
		Path:              args.Path,
		SeverityThreshold: types.SeverityLow,
	})
	if err != nil {
		return "", fmt.Errorf("scan failed: %w", err)
	}

	// Run dependency check
	depsResults, err := h.checker.Check(ctx, args.Path)
	if err != nil {
		// Non-fatal: continue without dep results
		depsResults = nil
	}

	// Generate report
	fullReport := report.NewFullReport(args.Path, scanResult, depsResults)
	return fullReport.Render(args.Format)
}
