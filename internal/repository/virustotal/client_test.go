package virustotal_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-ti/internal/repository/virustotal"
)

func testClient(t *testing.T, handler http.HandlerFunc) *virustotal.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return virustotal.New("test-key", virustotal.WithBaseURL(server.URL))
}

func TestURLStats(t *testing.T) {
	link := "https://example.com"
	wantID := base64.RawURLEncoding.EncodeToString([]byte(link))

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if key := r.Header.Get("x-apikey"); key != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/urls/"+wantID {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{
			"malicious":2,"suspicious":1,"harmless":80,"undetected":10,
			"timeout":1,"confirmed-timeout":2,"type-unsupported":3}}}}`))
	})

	stats, err := client.URLStats(context.Background(), link)
	if err != nil {
		t.Fatalf("URLStats() error = %v", err)
	}
	if stats.Malicious != 2 || stats.Suspicious != 1 || stats.Harmless != 80 || stats.Undetected != 10 {
		t.Errorf("unexpected stats: %+v", stats)
	}
	if stats.Timeout != 3 {
		t.Errorf("Timeout = %d, want 3", stats.Timeout)
	}
	if stats.Other["type-unsupported"] != 3 {
		t.Errorf("Other[type-unsupported] = %d, want 3", stats.Other["type-unsupported"])
	}
}

func TestFileStats(t *testing.T) {
	const sha256sum = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/files/"+sha256sum {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"harmless":60}}}}`))
	})

	stats, err := client.FileStats(context.Background(), sha256sum)
	if err != nil {
		t.Fatalf("FileStats() error = %v", err)
	}
	if stats.Malicious != 5 || stats.Harmless != 60 {
		t.Errorf("unexpected stats: %+v", stats)
	}
}

func TestNotFound(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	_, err := client.URLStats(context.Background(), "https://unknown.example.com")
	if !errors.Is(err, virustotal.ErrNotFound) {
		t.Errorf("URLStats() error = %v, want virustotal.ErrNotFound", err)
	}

	_, err = client.FileStats(context.Background(), "deadbeef")
	if !errors.Is(err, virustotal.ErrNotFound) {
		t.Errorf("FileStats() error = %v, want virustotal.ErrNotFound", err)
	}
}

func TestUnexpectedStatus(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Forbidden"}}`))
	})

	_, err := client.FileStats(context.Background(), "deadbeef")
	if err == nil {
		t.Fatal("FileStats() expected error on 403")
	}
	if errors.Is(err, virustotal.ErrNotFound) {
		t.Errorf("error = %v, should not be ErrNotFound", err)
	}
}
