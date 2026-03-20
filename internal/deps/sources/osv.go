package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mcp-sct/mcp-sct/internal/deps"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"
const osvQueryURL = "https://api.osv.dev/v1/query"
const maxBatchSize = 1000

// OSVClient queries the OSV.dev vulnerability database.
type OSVClient struct {
	client *http.Client
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *OSVClient) Name() string {
	return "OSV.dev"
}

// osvBatchRequest is the request body for the OSV batch API.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchResponse is the response from the OSV batch API.
type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvBatchResult struct {
	Vulns []osvVuln `json:"vulns,omitempty"`
}

type osvVuln struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Aliases   []string      `json:"aliases"`
	Severity  []osvSeverity `json:"severity,omitempty"`
	Affected  []osvAffected `json:"affected,omitempty"`
	References []osvRef     `json:"references,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage   `json:"package"`
	Ranges  []osvRange   `json:"ranges,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events,omitempty"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (o *OSVClient) Query(ctx context.Context, dependencies []deps.Dependency) ([]deps.VulnMatch, error) {
	if len(dependencies) == 0 {
		return nil, nil
	}

	var allMatches []deps.VulnMatch

	// Process in batches
	for i := 0; i < len(dependencies); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(dependencies) {
			end = len(dependencies)
		}
		batch := dependencies[i:end]

		matches, err := o.queryBatch(ctx, batch)
		if err != nil {
			return allMatches, fmt.Errorf("batch query failed: %w", err)
		}
		allMatches = append(allMatches, matches...)
	}

	return allMatches, nil
}

func (o *OSVClient) queryBatch(ctx context.Context, batch []deps.Dependency) ([]deps.VulnMatch, error) {
	req := osvBatchRequest{
		Queries: make([]osvQuery, len(batch)),
	}

	for i, dep := range batch {
		req.Queries[i] = osvQuery{
			Package: osvPackage{
				Name:      dep.Name,
				Ecosystem: dep.Ecosystem,
			},
			Version: dep.Version,
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	var matches []deps.VulnMatch
	for i, result := range batchResp.Results {
		if i >= len(batch) {
			break
		}
		dep := batch[i]
		for _, vuln := range result.Vulns {
			match := deps.VulnMatch{
				ID:         vuln.ID,
				Aliases:    vuln.Aliases,
				Summary:    vuln.Summary,
				Details:    truncate(vuln.Details, 500),
				Severity:   extractSeverity(vuln),
				FixVersion: extractFixVersion(vuln),
				References: extractRefs(vuln),
				Dependency: dep,
			}
			matches = append(matches, match)
		}
	}

	return matches, nil
}

func extractSeverity(vuln osvVuln) string {
	for _, s := range vuln.Severity {
		if s.Type == "CVSS_V3" {
			score := parseCVSSScore(s.Score)
			if score >= 9.0 {
				return "CRITICAL"
			} else if score >= 7.0 {
				return "HIGH"
			} else if score >= 4.0 {
				return "MEDIUM"
			}
			return "LOW"
		}
	}
	// Fallback: check ID prefix for severity hint
	return "UNKNOWN"
}

func parseCVSSScore(score string) float64 {
	// CVSS vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	// or just a numeric score
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil {
		return f
	}
	return 0
}

func extractFixVersion(vuln osvVuln) string {
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

func extractRefs(vuln osvVuln) []string {
	var refs []string
	for _, r := range vuln.References {
		refs = append(refs, r.URL)
	}
	if len(refs) > 5 {
		refs = refs[:5]
	}
	return refs
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
