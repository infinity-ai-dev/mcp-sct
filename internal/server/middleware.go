package server

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mcp-sct/mcp-sct/internal/auth"
)

// AuthMiddleware validates Bearer tokens on incoming requests.
func AuthMiddleware(store auth.TokenStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health checks
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		rawToken := strings.TrimPrefix(authHeader, "Bearer ")
		if rawToken == authHeader {
			http.Error(w, `{"error":"invalid Authorization format, use: Bearer <token>"}`, http.StatusUnauthorized)
			return
		}

		token, err := store.Validate(rawToken)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		// Add project context to request header for downstream use
		r.Header.Set("X-Project-ID", token.ProjectID)
		r.Header.Set("X-Token-ID", token.ID)

		// Pass through MCPize plan headers if present
		// MCPize gateway sets these headers based on the user's subscription
		if plan := r.Header.Get("X-MCPize-Plan"); plan != "" {
			r.Header.Set("X-Plan", plan)
		} else if plan := r.Header.Get("X-Subscription-Plan"); plan != "" {
			r.Header.Set("X-Plan", plan)
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimiter implements a simple per-IP token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // requests per window
	window   time.Duration
}

type visitor struct {
	count    int
	resetAt  time.Time
}

func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}
	// Cleanup goroutine
	go func() {
		for {
			time.Sleep(window)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for key, v := range rl.visitors {
		if now.After(v.resetAt) {
			delete(rl.visitors, key)
		}
	}
}

// Middleware returns an HTTP middleware that rate limits requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use project ID if available, otherwise IP
		key := r.Header.Get("X-Project-ID")
		if key == "" {
			key = r.RemoteAddr
		}

		if !rl.allow(key) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[key]
	if !ok || now.After(v.resetAt) {
		rl.visitors[key] = &visitor{
			count:   1,
			resetAt: now.Add(rl.window),
		}
		return true
	}

	if v.count >= rl.rate {
		return false
	}
	v.count++
	return true
}

// CORSMiddleware adds CORS headers for cloud mode.
func CORSMiddleware(allowedOrigins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs HTTP requests.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Printf("%s %s %d %s [project:%s]",
			r.Method, r.URL.Path, wrapped.statusCode,
			time.Since(start).Round(time.Millisecond),
			r.Header.Get("X-Project-ID"))
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
