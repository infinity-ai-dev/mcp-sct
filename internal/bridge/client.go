package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the Python AI Bridge via HTTP.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates an AI Bridge client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// AnalyzeRequest is sent to the Python AI service.
type AnalyzeRequest struct {
	Code              string            `json:"code"`
	Language          string            `json:"language"`
	FilePath          string            `json:"file_path,omitempty"`
	VulnerabilityType string            `json:"vulnerability_type,omitempty"`
	RuleID            string            `json:"rule_id,omitempty"`
	FindingMessage    string            `json:"finding_message,omitempty"`
	StartLine         int               `json:"start_line,omitempty"`
	EndLine           int               `json:"end_line,omitempty"`
	Context           map[string]string `json:"context,omitempty"`
}

// AnalyzeResponse is returned from the Python AI service.
type AnalyzeResponse struct {
	ModelUsed   string       `json:"model_used"`
	Error       string       `json:"error,omitempty"`
	Suggestions []Suggestion `json:"suggestions"`
}

// Suggestion is a single fix suggestion from the AI.
type Suggestion struct {
	FixedCode   string   `json:"fixed_code"`
	Explanation string   `json:"explanation"`
	Confidence  float64  `json:"confidence"`
	References  []string `json:"references,omitempty"`
}

// HealthStatus represents the AI bridge health.
type HealthStatus struct {
	Status         string                   `json:"status"`
	ActiveProvider string                   `json:"active_provider"`
	Providers      []map[string]interface{} `json:"providers"`
}

// Health checks if the AI bridge is running and which provider is active.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AI bridge unreachable: %w", err)
	}
	defer resp.Body.Close()

	var status HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

// Analyze sends code to the AI for security analysis.
func (c *Client) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	return c.post(ctx, "/analyze", req)
}

// SuggestFix sends a specific finding to the AI for a fix suggestion.
func (c *Client) SuggestFix(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	return c.post(ctx, "/suggest-fix", req)
}

func (c *Client) post(ctx context.Context, path string, payload interface{}) (*AnalyzeResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AI bridge request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI bridge error %d: %s", resp.StatusCode, string(respBody))
	}

	var result AnalyzeResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	return &result, nil
}
