package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mcp-sct/mcp-sct/internal/bridge"
	"github.com/mcp-sct/mcp-sct/internal/deps"
	"github.com/mcp-sct/mcp-sct/internal/scanner"
	"github.com/mcp-sct/mcp-sct/internal/tools"
)

type Server struct {
	mcpServer     *mcpserver.MCPServer
	scanHandler   *tools.ScanCodeHandler
	depsHandler   *tools.CheckDepsHandler
	fixesHandler  *tools.SuggestFixesHandler
	reportHandler *tools.GenerateReportHandler
	testHandler   *tools.RunSecurityTestHandler
	bridgeMgr     *bridge.Manager
}

func New(engine *scanner.Engine, checker *deps.Checker, bridgeMgr *bridge.Manager) *Server {
	s := &Server{
		scanHandler:   tools.NewScanCodeHandler(engine),
		depsHandler:   tools.NewCheckDepsHandler(checker),
		fixesHandler:  tools.NewSuggestFixesHandler(bridgeMgr),
		reportHandler: tools.NewGenerateReportHandler(engine, checker),
		testHandler:   tools.NewRunSecurityTestHandler(),
		bridgeMgr:     bridgeMgr,
	}

	s.mcpServer = mcpserver.NewMCPServer(
		"mcp-sct",
		"0.4.0",
		mcpserver.WithToolCapabilities(false),
	)

	s.registerTools()
	return s
}

func (s *Server) registerTools() {
	// 1. scan_code
	s.mcpServer.AddTool(
		mcp.NewTool("scan_code",
			mcp.WithDescription(
				"Perform static security analysis on source code. "+
					"Scans for OWASP Top 10 vulnerabilities: SQL injection, XSS, "+
					"command injection, hardcoded secrets, path traversal, deserialization, "+
					"weak crypto, SSRF, prototype pollution, XXE. "+
					"Supports Python, JavaScript, TypeScript, Go, and Java.",
			),
			mcp.WithString("path", mcp.Required(),
				mcp.Description("Absolute path to a file or directory to scan")),
			mcp.WithString("language",
				mcp.Description("Filter to specific language: python, javascript, typescript, go, java")),
			mcp.WithString("severity_threshold",
				mcp.Description("Minimum severity: LOW, MEDIUM, HIGH, CRITICAL. Default: LOW")),
		),
		s.handleScanCode,
	)

	// 2. check_dependencies
	s.mcpServer.AddTool(
		mcp.NewTool("check_dependencies",
			mcp.WithDescription(
				"Check project dependencies for known CVEs. "+
					"Parses go.mod, package.json, package-lock.json, requirements.txt. "+
					"Queries OSV.dev vulnerability database.",
			),
			mcp.WithString("path", mcp.Required(),
				mcp.Description("Absolute path to project directory or lockfile")),
		),
		s.handleCheckDeps,
	)

	// 3. suggest_fixes
	s.mcpServer.AddTool(
		mcp.NewTool("suggest_fixes",
			mcp.WithDescription(
				"Get AI-powered fix suggestions for a security vulnerability. "+
					"Uses LLM analysis (Ollama/OpenAI/Anthropic) to generate secure code fixes. "+
					"Falls back to rule-based suggestions if no AI provider is configured.",
			),
			mcp.WithString("code", mcp.Required(),
				mcp.Description("The vulnerable code snippet to fix")),
			mcp.WithString("language", mcp.Required(),
				mcp.Description("Programming language: python, javascript, typescript, go, java")),
			mcp.WithString("vulnerability_type",
				mcp.Description("Type: 'sql injection', 'xss', 'command injection', etc.")),
			mcp.WithString("file_path",
				mcp.Description("Source file path for context")),
			mcp.WithString("rule_id",
				mcp.Description("MCP-SCT rule ID that detected the vulnerability")),
			mcp.WithString("finding_message",
				mcp.Description("Original finding message from scan_code")),
		),
		s.handleSuggestFixes,
	)

	// 4. generate_report
	s.mcpServer.AddTool(
		mcp.NewTool("generate_report",
			mcp.WithDescription(
				"Generate a consolidated security report. "+
					"Runs both code scan and dependency check, then produces "+
					"a report in Markdown, JSON, or SARIF format. "+
					"SARIF format integrates with GitHub Code Scanning and GitLab SAST.",
			),
			mcp.WithString("path", mcp.Required(),
				mcp.Description("Absolute path to the project directory")),
			mcp.WithString("format",
				mcp.Description("Output format: markdown (default), json, sarif")),
		),
		s.handleGenerateReport,
	)

	// 5. run_security_test
	s.mcpServer.AddTool(
		mcp.NewTool("run_security_test",
			mcp.WithDescription(
				"Run external security testing tools on the codebase. "+
					"Supports: semgrep (multi-language SAST), bandit (Python), "+
					"gosec (Go), npm audit (JS deps). "+
					"Auto-detects which tools are installed.",
			),
			mcp.WithString("path", mcp.Required(),
				mcp.Description("Absolute path to the project directory")),
			mcp.WithString("tool",
				mcp.Description("Run a specific tool: semgrep, bandit, gosec, 'npm audit'")),
			mcp.WithNumber("timeout",
				mcp.Description("Timeout in seconds (default: 120)")),
		),
		s.handleRunSecurityTest,
	)

	// 6. get_security_guidelines
	s.mcpServer.AddTool(
		mcp.NewTool("get_security_guidelines",
			mcp.WithDescription(
				"Get security best practices for a specific topic. "+
					"13+ topics: sql injection, xss, csrf, authentication, "+
					"secrets management, cryptography, cors, docker security, "+
					"api security, deserialization, logging, error handling, "+
					"input validation, path traversal, command injection.",
			),
			mcp.WithString("topic", mcp.Required(),
				mcp.Description("Security topic to get guidelines for")),
			mcp.WithString("language",
				mcp.Description("Programming language context: python, javascript, go, java")),
		),
		s.handleGetGuidelines,
	)
}

func (s *Server) handleScanCode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args tools.ScanCodeArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := s.scanHandler.Handle(ctx, args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan error: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func (s *Server) handleCheckDeps(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args tools.CheckDepsArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := s.depsHandler.Handle(ctx, args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("dependency check error: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func (s *Server) handleSuggestFixes(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args tools.SuggestFixesArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := s.fixesHandler.Handle(ctx, args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("suggest fixes error: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func (s *Server) handleGenerateReport(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args tools.GenerateReportArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := s.reportHandler.Handle(ctx, args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("report error: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func (s *Server) handleRunSecurityTest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args tools.RunSecurityTestArgs
	if err := unmarshalArgs(req, &args); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	result, err := s.testHandler.Handle(ctx, args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("security test error: %v", err)), nil
	}
	return mcp.NewToolResultText(result), nil
}

func (s *Server) handleGetGuidelines(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	topic, _ := args["topic"].(string)
	language, _ := args["language"].(string)
	if topic == "" {
		return mcp.NewToolResultError("topic is required"), nil
	}
	return mcp.NewToolResultText(getGuidelines(topic, language)), nil
}

func (s *Server) ServeStdio() error {
	log.Println("MCP-SCT server starting (stdio transport)...")
	return mcpserver.ServeStdio(s.mcpServer)
}

func (s *Server) Shutdown() {
	if s.bridgeMgr != nil {
		s.bridgeMgr.Stop()
	}
}

func unmarshalArgs(request mcp.CallToolRequest, target interface{}) error {
	argsJSON, err := json.Marshal(request.GetArguments())
	if err != nil {
		return fmt.Errorf("invalid arguments: %v", err)
	}
	return json.Unmarshal(argsJSON, target)
}
