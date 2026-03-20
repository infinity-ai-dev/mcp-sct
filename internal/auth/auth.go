package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Token represents a project access token.
type Token struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Hash      string    `json:"-"` // SHA-256 hash of the raw token
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Scopes    []string  `json:"scopes"` // e.g., ["scan", "deps", "report"]
}

func (t *Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.ExpiresAt)
}

func (t *Token) HasScope(scope string) bool {
	if len(t.Scopes) == 0 {
		return true // empty scopes = all access
	}
	for _, s := range t.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// TokenStore manages project tokens.
type TokenStore interface {
	Validate(rawToken string) (*Token, error)
	Create(projectID, name string, scopes []string, ttl time.Duration) (rawToken string, token *Token, err error)
	Revoke(tokenID string) error
	ListByProject(projectID string) ([]*Token, error)
}

// InMemoryTokenStore is a simple in-memory token store for self-hosted mode.
type InMemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token // keyed by hash
}

func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make(map[string]*Token),
	}
}

func (s *InMemoryTokenStore) Validate(rawToken string) (*Token, error) {
	hash := hashToken(rawToken)

	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.tokens[hash]
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}
	if token.IsExpired() {
		return nil, fmt.Errorf("token expired")
	}
	return token, nil
}

// RegisterFixed registers a pre-defined token (e.g., from env var).
func (s *InMemoryTokenStore) RegisterFixed(rawToken, projectID, name string) {
	token := &Token{
		ID:        generateID(),
		ProjectID: projectID,
		Hash:      hashToken(rawToken),
		Name:      name,
		CreatedAt: time.Now(),
		Scopes:    []string{"*"},
	}
	s.mu.Lock()
	s.tokens[token.Hash] = token
	s.mu.Unlock()
}

func (s *InMemoryTokenStore) Create(projectID, name string, scopes []string, ttl time.Duration) (string, *Token, error) {
	raw, err := generateToken()
	if err != nil {
		return "", nil, err
	}

	token := &Token{
		ID:        generateID(),
		ProjectID: projectID,
		Hash:      hashToken(raw),
		Name:      name,
		CreatedAt: time.Now(),
		Scopes:    scopes,
	}
	if ttl > 0 {
		token.ExpiresAt = time.Now().Add(ttl)
	}

	s.mu.Lock()
	s.tokens[token.Hash] = token
	s.mu.Unlock()

	return raw, token, nil
}

func (s *InMemoryTokenStore) Revoke(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, t := range s.tokens {
		if t.ID == tokenID {
			delete(s.tokens, hash)
			return nil
		}
	}
	return fmt.Errorf("token not found")
}

func (s *InMemoryTokenStore) ListByProject(projectID string) ([]*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Token
	for _, t := range s.tokens {
		if t.ProjectID == projectID {
			result = append(result, t)
		}
	}
	return result, nil
}

// hashToken computes SHA-256 of a raw token.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// generateToken creates a cryptographically secure random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mcp_" + hex.EncodeToString(b), nil
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ConstantTimeCompare compares two strings in constant time.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
