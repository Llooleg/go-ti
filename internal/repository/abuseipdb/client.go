// Package abuseipdb is a data access adapter for the AbuseIPDB v2 API.
package abuseipdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"go-ti/internal/domain"
)

const defaultBaseURL = "https://api.abuseipdb.com/api/v2"

// maxResponseSize limits how much of an API response is read into memory.
const maxResponseSize = 10 << 20 // 10 MiB

// ErrNotFound is returned when AbuseIPDB has no report for the requested IP.
var ErrNotFound = errors.New("abuseipdb: report not found")

// Client queries the AbuseIPDB v2 API. It is safe for concurrent use.
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

// New creates an AbuseIPDB client authenticated with the given API key.
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

type apiResponse struct {
	Data domain.AbuseReport `json:"data"`
}

// CheckIP returns the abuse report for the given IPv4 or IPv6 address.
func (c *Client) CheckIP(ctx context.Context, ip string) (domain.AbuseReport, error) {
	endpoint := fmt.Sprintf("%s/check?ipAddress=%s", c.baseURL, url.QueryEscape(ip))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.AbuseReport{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return domain.AbuseReport{}, fmt.Errorf("execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return domain.AbuseReport{}, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return domain.AbuseReport{}, fmt.Errorf("%w: %s", ErrNotFound, ip)
	default:
		return domain.AbuseReport{}, fmt.Errorf("unexpected status %s: %s", resp.Status, string(body))
	}

	var payload apiResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return domain.AbuseReport{}, fmt.Errorf("decode response: %w", err)
	}

	return payload.Data, nil
}
