package abuseipdb_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-ti/internal/repository/abuseipdb"
)

func testClient(t *testing.T, handler http.HandlerFunc) *abuseipdb.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return abuseipdb.New("test-key", abuseipdb.WithBaseURL(server.URL))
}

func TestCheckIP(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if key := r.Header.Get("Key"); key != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/check" || r.URL.Query().Get("ipAddress") != "127.0.0.1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{
			"ipAddress":"127.0.0.1","isPublic":true,"ipVersion":4,
			"isWhitelisted":true,"abuseConfidenceScore":0,"countryCode":"",
			"usageType":"Fixed Line ISP","isp":"Loopback","domain":"",
			"hostnames":[],"totalReports":0,"numDistinctUsers":0,
			"lastReportedAt":""}}`))
	})

	report, err := client.CheckIP(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("CheckIP() error = %v", err)
	}
	if report.IPAddress != "127.0.0.1" || report.AbuseConfidenceScore != 0 || !report.IsWhitelisted {
		t.Errorf("unexpected report: %+v", report)
	}
	if report.UsageType != "Fixed Line ISP" || report.ISP != "Loopback" {
		t.Errorf("unexpected usage info: %+v", report)
	}
}

func TestCheckIPNotFound(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	_, err := client.CheckIP(context.Background(), "10.0.0.1")
	if !errors.Is(err, abuseipdb.ErrNotFound) {
		t.Errorf("CheckIP() error = %v, want abuseipdb.ErrNotFound", err)
	}
}

func TestCheckIPUnexpectedStatus(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"rate limited"}]}`))
	})

	_, err := client.CheckIP(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("CheckIP() expected error on 429")
	}
}
