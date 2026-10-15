package web_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-ti/internal/delivery/web"
	"go-ti/internal/domain"
)

type stubService struct {
	result  domain.AnalysisResult
	err     error
	gotInpt string
}

func (s *stubService) Analyze(_ context.Context, input string) (domain.AnalysisResult, error) {
	s.gotInpt = input
	return s.result, s.err
}

func newTestServer(t *testing.T, service web.AnalysisService) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(web.New(service, logger).Handler())
	t.Cleanup(server.Close)
	return server
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func postJSON(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(data)
}

func sampleResult() domain.AnalysisResult {
	return domain.AnalysisResult{
		Input:      "https://example.com",
		Kind:       domain.InputKindLink,
		ResolvedIP: "93.184.216.34",
		Stats:      domain.AnalysisStats{Malicious: 2, Suspicious: 1, Harmless: 80, Undetected: 10, Timeout: 3},
		Abuse: &domain.AbuseReport{
			IPAddress:            "93.184.216.34",
			AbuseConfidenceScore: 5,
			CountryCode:          "US",
		},
	}
}

func TestAnalyzeSuccess(t *testing.T) {
	svc := &stubService{result: sampleResult()}
	server := newTestServer(t, svc)

	status, body := postJSON(t, server.URL+"/api/analyze", `{"input":" https://example.com "}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", status, http.StatusOK, body)
	}
	if svc.gotInpt != "https://example.com" {
		t.Errorf("service got input %q", svc.gotInpt)
	}

	for _, want := range []string{
		`"kind":"link"`,
		`"malicious":2`,
		`"harmless":80`,
		`"resolvedIp":"93.184.216.34"`,
		`"ipAddress":"93.184.216.34"`,
		`"abuseConfidenceScore":5`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %s\nresponse: %s", want, body)
		}
	}
	if strings.Contains(body, `"warning"`) || strings.Contains(body, `"error"`) {
		t.Errorf("unexpected warning/error in successful response: %s", body)
	}
}

func TestAnalyzePartialResult(t *testing.T) {
	svc := &stubService{result: sampleResult(), err: errors.New("abuseipdb check: boom")}
	server := newTestServer(t, svc)

	status, body := postJSON(t, server.URL+"/api/analyze", `{"input":"https://example.com"}`)
	if status != http.StatusOK {
		t.Fatalf("partial result should still return 200, got %d: %s", status, body)
	}
	if !strings.Contains(body, `"warning":"abuseipdb check: boom"`) {
		t.Errorf("response missing warning: %s", body)
	}
	if !strings.Contains(body, `"kind":"link"`) {
		t.Errorf("response missing partial result: %s", body)
	}
}

func TestAnalyzeFailure(t *testing.T) {
	svc := &stubService{err: errors.New("hash file: no such file")}
	server := newTestServer(t, svc)

	status, body := postJSON(t, server.URL+"/api/analyze", `{"input":"/missing/file"}`)
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", status, http.StatusInternalServerError)
	}
	if !strings.Contains(body, `"error":"hash file: no such file"`) {
		t.Errorf("response missing error: %s", body)
	}
}

func TestAnalyzeBadRequest(t *testing.T) {
	svc := &stubService{}
	server := newTestServer(t, svc)

	cases := []struct {
		name string
		body string
	}{
		{"empty input", `{"input":"   "}`},
		{"invalid json", `not json`},
		{"unknown field", `{"input":"x","extra":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := postJSON(t, server.URL+"/api/analyze", tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
			}
		})
	}
	if svc.gotInpt != "" {
		t.Errorf("service must not be called on bad requests, got input %q", svc.gotInpt)
	}
}

func TestAnalyzeMethodNotAllowed(t *testing.T) {
	server := newTestServer(t, &stubService{})

	status, _ := get(t, server.URL+"/api/analyze")
	if status != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/analyze status = %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestIndexPage(t *testing.T) {
	server := newTestServer(t, &stubService{})

	status, body := get(t, server.URL+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if !strings.Contains(body, "go-ti") || !strings.Contains(body, "lookup-form") {
		t.Errorf("unexpected index page: %s", body)
	}
}

func TestStaticAssets(t *testing.T) {
	server := newTestServer(t, &stubService{})

	for path, want := range map[string]string{
		"/static/app.js":    "fetch('/api/analyze'",
		"/static/style.css": "--bad",
	} {
		status, body := get(t, server.URL+path)
		if status != http.StatusOK {
			t.Errorf("GET %s status = %d, want %d", path, status, http.StatusOK)
			continue
		}
		if !strings.Contains(body, want) {
			t.Errorf("GET %s body missing %q", path, want)
		}
	}
}

func TestHealth(t *testing.T) {
	server := newTestServer(t, &stubService{})

	status, body := get(t, server.URL+"/api/health")
	if status != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("health = %d %s", status, body)
	}
}

func TestSecurityHeaders(t *testing.T) {
	server := newTestServer(t, &stubService{})

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}
