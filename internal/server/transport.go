package server

import (
	"fmt"
	"log"
	"net/http"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mcp-sct/mcp-sct/internal/auth"
)

// CloudConfig holds HTTP transport configuration.
type CloudConfig struct {
	Address        string
	TokenStore     auth.TokenStore
	EnableAuth     bool
	RateLimit      int           // requests per minute
	AllowedOrigins []string
}

// ServeHTTP starts the MCP server with Streamable HTTP transport.
func (s *Server) ServeHTTP(cfg CloudConfig) error {
	if cfg.Address == "" {
		cfg.Address = ":8080"
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 60
	}
	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{"*"}
	}

	// Create Streamable HTTP transport (stateless for MCPize gateway compatibility)
	httpServer := mcpserver.NewStreamableHTTPServer(s.mcpServer,
		mcpserver.WithStateLess(true),
	)

	// Build middleware chain
	var handler http.Handler = httpServer

	// Rate limiting
	rl := NewRateLimiter(cfg.RateLimit, time.Minute)
	handler = rl.Middleware(handler)

	// Authentication
	if cfg.EnableAuth && cfg.TokenStore != nil {
		handler = AuthMiddleware(cfg.TokenStore, handler)
	}

	// CORS
	handler = CORSMiddleware(cfg.AllowedOrigins, handler)

	// Logging
	handler = LoggingMiddleware(handler)

	// Health endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"0.5.0","mode":"cloud"}`)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)
	// MCPize gateway sends requests to root path
	mux.Handle("/", handler)

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("MCP-SCT cloud server starting on %s", cfg.Address)
	log.Printf("Auth: %v | Rate limit: %d/min | CORS: %v", cfg.EnableAuth, cfg.RateLimit, cfg.AllowedOrigins)

	return server.ListenAndServe()
}
