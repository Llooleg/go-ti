// Package virustotal is a data access adapter for the VirusTotal v3 API.
package virustotal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go-ti/internal/domain"
)

const defaultBaseURL = "https://www.virustotal.com/api/v3"

// maxResponseSize limits how much of an API response is read into memory.
const maxResponseSize = 10 << 20 // 10 MiB

// ErrNotFound is returned when VirusTotal has no report for the requested item.
var ErrNotFound = errors.New("virustotal: report not found")

// Client queries the VirusTotal v3 API. It is safe for concurrent use.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// Option customizes a Client.
type Option func(*Client)

// WithBaseURL overrides the API base URL (useful in tests and proxies).
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// New creates a VirusTotal client authenticated with the given API key.
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// URLStats returns the last analysis stats for the given URL.
func (c *Client) URLStats(ctx context.Context, rawURL string) (domain.AnalysisStats, error) {
	id := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(rawURL)))
	return c.fetchStats(ctx, "/urls/"+id)
}

// FileStats returns the last analysis stats for the file with the given SHA-256.
func (c *Client) FileStats(ctx context.Context, sha256 string) (domain.AnalysisStats, error) {
	return c.fetchStats(ctx, "/files/"+sha256)
}

type apiReport struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats map[string]int `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func (c *Client) fetchStats(ctx context.Context, path string) (domain.AnalysisStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return domain.AnalysisStats{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return domain.AnalysisStats{}, fmt.Errorf("execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return domain.AnalysisStats{}, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return domain.AnalysisStats{}, fmt.Errorf("%w: %s", ErrNotFound, path)
	default:
		return domain.AnalysisStats{}, fmt.Errorf("unexpected status %s: %s", resp.Status, string(body))
	}

	var report apiReport
	if err := json.Unmarshal(body, &report); err != nil {
		return domain.AnalysisStats{}, fmt.Errorf("decode response: %w", err)
	}

	return domain.NewAnalysisStats(report.Data.Attributes.LastAnalysisStats), nil
}
