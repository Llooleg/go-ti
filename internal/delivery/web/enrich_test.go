package web_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-ti/internal/delivery/web"
	"go-ti/internal/domain"
)

type stubEnricher struct {
	response domain.EnrichmentResponse
	gotAlert map[string]any
	calls    int
}

func (s *stubEnricher) Enrich(_ context.Context, alert map[string]any) domain.EnrichmentResponse {
	s.calls++
	s.gotAlert = alert
	return s.response
}

func newEnrichTestServer(t *testing.T, enricher web.EnrichmentService, token string) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(
		web.New(&stubService{}, logger, web.WithEnrichment(enricher, token, 0)).Handler(),
	)
	t.Cleanup(server.Close)
	return server
}

func postJSONWithAuth(t *testing.T, url, body, auth string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)

	resp, err := http.DefaultClient.Do(req)
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

func sampleEnrichmentResponse() domain.EnrichmentResponse {
	return domain.EnrichmentResponse{
		Enrichments: []domain.EnrichmentResult{
			{
				IOC:     domain.IOC{Type: domain.IOCTypeFileHash, Value: "ab12", Algo: "sha256"},
				Verdict: domain.VerdictMalicious,
				Stats:   &domain.AnalysisStats{Malicious: 41},
			},
		},
		Summary: domain.EnrichmentSummary{IOCsFound: 1, LookedUp: 1, Malicious: 1},
	}
}

func TestEnrichSuccess(t *testing.T) {
	enricher := &stubEnricher{response: sampleEnrichmentResponse()}
	server := newEnrichTestServer(t, enricher, "")

	status, body := postJSON(t, server.URL+"/api/enrich",
		`{"agent":{"id":"001"},"data":{"syscheck":{"sha256_after":"ab12"}}}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", status, http.StatusOK, body)
	}

	if enricher.calls != 1 {
		t.Errorf("enricher called %d times, want 1", enricher.calls)
	}
	if enricher.gotAlert == nil || enricher.gotAlert["agent"] == nil {
		t.Errorf("alert payload not passed through: %+v", enricher.gotAlert)
	}
	for _, want := range []string{
		`"verdict":"malicious"`,
		`"algo":"sha256"`,
		`"iocs_found":1`,
		`"malicious":1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %s\nresponse: %s", want, body)
		}
	}
}

func TestEnrichBadRequest(t *testing.T) {
	enricher := &stubEnricher{}
	server := newEnrichTestServer(t, enricher, "")

	cases := []struct {
		name string
		body string
	}{
		{"invalid json", `not json`},
		{"null body", `null`},
		{"json array", `[1,2,3]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := postJSON(t, server.URL+"/api/enrich", tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
			}
		})
	}
	if enricher.calls != 0 {
		t.Errorf("enricher must not be called on bad requests, got %d calls", enricher.calls)
	}
}

func TestEnrichMethodNotAllowed(t *testing.T) {
	server := newEnrichTestServer(t, &stubEnricher{}, "")

	status, _ := get(t, server.URL+"/api/enrich")
	if status != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/enrich status = %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestEnrichNotConfigured(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(web.New(&stubService{}, logger).Handler())
	t.Cleanup(server.Close)

	status, _ := postJSON(t, server.URL+"/api/enrich", `{}`)
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", status, http.StatusServiceUnavailable)
	}
}

func TestBearerAuth(t *testing.T) {
	enricher := &stubEnricher{response: sampleEnrichmentResponse()}
	server := newEnrichTestServer(t, enricher, "s3cret")

	t.Run("missing token", func(t *testing.T) {
		status, _ := postJSON(t, server.URL+"/api/enrich", `{}`)
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		status, _ := postJSONWithAuth(t, server.URL+"/api/enrich", `{}`, "Bearer wrong")
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("correct token", func(t *testing.T) {
		status, _ := postJSONWithAuth(t, server.URL+"/api/enrich", `{}`, "Bearer s3cret")
		if status != http.StatusOK {
			t.Errorf("status = %d, want %d", status, http.StatusOK)
		}
	})

	t.Run("analyze also requires token", func(t *testing.T) {
		status, _ := postJSON(t, server.URL+"/api/analyze", `{"input":"https://example.com"}`)
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
		}
	})
}
