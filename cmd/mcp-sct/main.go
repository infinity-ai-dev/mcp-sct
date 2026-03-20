package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mcp-sct/mcp-sct/internal/auth"
	"github.com/mcp-sct/mcp-sct/internal/bridge"
	"github.com/mcp-sct/mcp-sct/internal/config"
	"github.com/mcp-sct/mcp-sct/internal/deps"
	"github.com/mcp-sct/mcp-sct/internal/deps/parsers"
	"github.com/mcp-sct/mcp-sct/internal/deps/sources"
	"github.com/mcp-sct/mcp-sct/internal/rules"
	"github.com/mcp-sct/mcp-sct/internal/rules/builtin"
	"github.com/mcp-sct/mcp-sct/internal/scanner"
	"github.com/mcp-sct/mcp-sct/internal/server"
	"github.com/mcp-sct/mcp-sct/internal/storage"
)

var (
	version  = "0.6.0"
	cfgPath  = flag.String("config", "", "Path to configuration file")
	rulesDir = flag.String("rules-dir", "", "Path to custom rules directory")
	enableAI = flag.Bool("ai", false, "Enable AI bridge for intelligent fix suggestions")
	mode     = flag.String("mode", "", "Server mode: stdio (default) or cloud")
	addr     = flag.String("addr", ":8080", "HTTP listen address (cloud mode)")
	showVer  = flag.Bool("version", false, "Show version and exit")
)

func main() {
	flag.Parse()

	if *showVer {
		fmt.Printf("mcp-sct v%s\n", version)
		os.Exit(0)
	}

	log.SetOutput(os.Stderr)
	log.SetPrefix("[mcp-sct] ")

	// Load config
	cfg := config.DefaultConfig()
	if *cfgPath != "" {
		var err error
		cfg, err = config.LoadFromFile(*cfgPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// CLI overrides
	if *rulesDir != "" {
		cfg.CustomRulesDirs = append(cfg.CustomRulesDirs, *rulesDir)
	}
	if *enableAI {
		cfg.AIBridgeEnabled = true
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if *addr != "" {
		cfg.Address = *addr
	}

	// Env overrides
	if os.Getenv("MCP_SCT_AI_ENABLED") == "true" || os.Getenv("MCP_SCT_AI_ENABLED") == "1" {
		cfg.AIBridgeEnabled = true
	}
	if envMode := os.Getenv("MCP_SCT_MODE"); envMode != "" {
		cfg.Mode = envMode
	}
	if envAddr := os.Getenv("MCP_SCT_ADDR"); envAddr != "" {
		cfg.Address = envAddr
	}
	// MCPize/Heroku-style PORT env var
	if port := os.Getenv("PORT"); port != "" {
		cfg.Address = ":" + port
	}

	// Initialize rules
	registry := rules.NewRegistry()

	if cfg.BuiltinRulesEnabled {
		rulesFS, err := fs.Sub(builtin.RulesFS, "rules")
		if err != nil {
			log.Fatalf("Failed to access builtin rules: %v", err)
		}
		builtinRules, err := rules.LoadFromFS(rulesFS)
		if err != nil {
			log.Fatalf("Failed to load builtin rules: %v", err)
		}
		if err := registry.RegisterAll(builtinRules); err != nil {
			log.Fatalf("Failed to register builtin rules: %v", err)
		}
		log.Printf("Loaded %d builtin rules", len(builtinRules))
	}

	for _, dir := range cfg.CustomRulesDirs {
		customRules, err := rules.LoadFromDir(dir)
		if err != nil {
			log.Printf("Warning: failed to load rules from %s: %v", dir, err)
			continue
		}
		if len(customRules) > 0 {
			if err := registry.RegisterAll(customRules); err != nil {
				log.Printf("Warning: failed to register rules from %s: %v", dir, err)
			}
			log.Printf("Loaded %d custom rules from %s", len(customRules), dir)
		}
	}

	log.Printf("Total rules registered: %d", registry.Count())

	// Initialize scanner
	engine := scanner.NewEngine(registry, cfg.Workers, cfg.MaxFileSize, cfg.ExcludePatterns)

	// Initialize dependency checker
	depParsers := []deps.Parser{}
	for _, p := range parsers.All() {
		depParsers = append(depParsers, p)
	}
	checker := deps.NewChecker(depParsers, []deps.VulnSource{sources.NewOSVClient()})

	// Initialize AI bridge (optional)
	var bridgeMgr *bridge.Manager
	if cfg.AIBridgeEnabled {
		pythonPath := cfg.PythonPath
		if envPy := os.Getenv("MCP_SCT_PYTHON_PATH"); envPy != "" {
			pythonPath = envPy
		}
		scriptPath := cfg.AIScriptPath
		if envScript := os.Getenv("MCP_SCT_AI_SCRIPT"); envScript != "" {
			scriptPath = envScript
		}

		bridgeMgr = bridge.NewManager(pythonPath, scriptPath, cfg.AIBridgePort)

		// Start AI bridge in background - don't block server startup
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := bridgeMgr.Start(ctx); err != nil {
				log.Printf("Warning: AI bridge failed to start: %v", err)
				log.Printf("suggest_fixes will use rule-based fallback")
			}
		}()
	} else {
		log.Println("AI bridge disabled. Use --ai or MCP_SCT_AI_ENABLED=true to enable.")
	}

	// Initialize storage (PostgreSQL if DATABASE_URL set, otherwise in-memory)
	var store storage.Store
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		pgStore, err := storage.NewPostgresStore(dbURL)
		if err != nil {
			log.Printf("Warning: failed to connect to PostgreSQL: %v", err)
			log.Println("Falling back to in-memory storage")
		} else {
			store = pgStore
			log.Println("Connected to PostgreSQL")
			defer store.Close()
		}
	} else {
		log.Println("Using in-memory storage (set DATABASE_URL for persistence)")
	}
	_ = store // used by server in future for scan history persistence

	// Create MCP server
	srv := server.New(engine, checker, bridgeMgr)

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		srv.Shutdown()
		os.Exit(0)
	}()

	// Start in the appropriate mode
	switch strings.ToLower(cfg.Mode) {
	case "cloud", "http":
		tokenStore := auth.NewInMemoryTokenStore()

		// Create a default admin token for cloud mode
		enableAuth := true
		if envToken := os.Getenv("MCP_SCT_ADMIN_TOKEN"); envToken != "" {
			// Register the fixed token in the store
			tokenStore.RegisterFixed(envToken, "default", "admin")
			log.Println("Using MCP_SCT_ADMIN_TOKEN for authentication")
		} else if os.Getenv("MCP_SCT_NO_AUTH") == "true" {
			enableAuth = false
			log.Println("WARNING: Authentication disabled (MCP_SCT_NO_AUTH=true)")
		} else {
			raw, _, err := tokenStore.Create("default", "admin", []string{"*"}, 0)
			if err != nil {
				log.Fatalf("Failed to create admin token: %v", err)
			}
			log.Printf("Generated admin token: %s", raw)
			log.Println("Set MCP_SCT_ADMIN_TOKEN env var to use a fixed token")
		}

		cloudCfg := server.CloudConfig{
			Address:    cfg.Address,
			TokenStore: tokenStore,
			EnableAuth: enableAuth,
			RateLimit:  60,
		}

		if err := srv.ServeHTTP(cloudCfg); err != nil {
			srv.Shutdown()
			log.Fatalf("HTTP server error: %v", err)
		}

	default: // stdio
		if err := srv.ServeStdio(); err != nil {
			srv.Shutdown()
			log.Fatalf("Server error: %v", err)
		}
	}
}
