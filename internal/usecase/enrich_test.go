package usecase_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"go-ti/internal/domain"
	"go-ti/internal/usecase"
	"go-ti/pkg/ratelimit"
)

const testSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func newTestEnricher(t *testing.T, vt usecase.VirusTotal, abuse usecase.AbuseIPDB, resolver usecase.Resolver) *usecase.EnrichmentService {
	t.Helper()
	svc, err := usecase.NewEnrichmentService(usecase.EnrichmentDeps{
		VirusTotal:        vt,
		Abuse:             abuse,
		Resolver:          resolver,
		Extractor:         usecase.NewIOCExtractor(10, nil),
		Cache:             usecase.NewVerdictCache(time.Hour),
		VirusTotalLimiter: ratelimit.New(100000),
		AbuseLimiter:      ratelimit.New(100000),
	})
	if err != nil {
		t.Fatalf("NewEnrichmentService() error = %v", err)
	}
	return svc
}

func syscheckAlert() map[string]any {
	return map[string]any{
		"agent": map[string]any{"id": "001"},
		"data": map[string]any{
			"syscheck": map[string]any{"path": "/tmp/x", "sha256_after": testSHA256},
		},
	}
}

func TestEnrichFileHashVerdicts(t *testing.T) {
	t.Run("malicious", func(t *testing.T) {
		vt := &stubVirusTotal{hashStats: domain.AnalysisStats{Malicious: 3, Harmless: 60}}
		resp := newTestEnricher(t, vt, &stubAbuseIPDB{}, &stubResolver{}).Enrich(context.Background(), syscheckAlert())

		if len(resp.Enrichments) != 1 {
			t.Fatalf("got %d enrichments, want 1", len(resp.Enrichments))
		}
		res := resp.Enrichments[0]
		if res.Verdict != domain.VerdictMalicious {
			t.Errorf("verdict = %q, want malicious", res.Verdict)
		}
		if vt.gotHash != "sha256:"+testSHA256 {
			t.Errorf("HashStats got %q", vt.gotHash)
		}
		if resp.Summary.Malicious != 1 || resp.Summary.LookedUp != 1 || resp.Summary.Failures != 0 {
			t.Errorf("unexpected summary: %+v", resp.Summary)
		}
	})

	t.Run("clean", func(t *testing.T) {
		vt := &stubVirusTotal{hashStats: domain.AnalysisStats{Harmless: 70}}
		resp := newTestEnricher(t, vt, &stubAbuseIPDB{}, &stubResolver{}).Enrich(context.Background(), syscheckAlert())
		if resp.Enrichments[0].Verdict != domain.VerdictClean {
			t.Errorf("verdict = %q, want clean", resp.Enrichments[0].Verdict)
		}
	})

	t.Run("lookup failure is not cached", func(t *testing.T) {
		vt := &stubVirusTotal{hashErr: context.DeadlineExceeded}
		svc := newTestEnricher(t, vt, &stubAbuseIPDB{}, &stubResolver{})

		for i := 0; i < 2; i++ {
			resp := svc.Enrich(context.Background(), syscheckAlert())
			if resp.Enrichments[0].Verdict != domain.VerdictUnknown {
				t.Errorf("run %d: verdict = %q, want unknown", i, resp.Enrichments[0].Verdict)
			}
			if resp.Summary.Failures != 1 {
				t.Errorf("run %d: failures = %d, want 1", i, resp.Summary.Failures)
			}
		}
		if vt.gotHashes != 2 {
			t.Errorf("failed lookups must be retried, HashStats called %d times, want 2", vt.gotHashes)
		}
	})
}

func TestEnrichIPVerdicts(t *testing.T) {
	alert := map[string]any{"srcip": "8.8.8.8"}

	t.Run("suspicious on high confidence", func(t *testing.T) {
		abuse := &stubAbuseIPDB{report: domain.AbuseReport{IPAddress: "8.8.8.8", AbuseConfidenceScore: 75}}
		resp := newTestEnricher(t, &stubVirusTotal{}, abuse, &stubResolver{}).Enrich(context.Background(), alert)
		if resp.Enrichments[0].Verdict != domain.VerdictSuspicious {
			t.Errorf("verdict = %q, want suspicious", resp.Enrichments[0].Verdict)
		}
	})

	t.Run("clean on low confidence", func(t *testing.T) {
		abuse := &stubAbuseIPDB{report: domain.AbuseReport{IPAddress: "8.8.8.8", AbuseConfidenceScore: 5}}
		resp := newTestEnricher(t, &stubVirusTotal{}, abuse, &stubResolver{}).Enrich(context.Background(), alert)
		if resp.Enrichments[0].Verdict != domain.VerdictClean {
			t.Errorf("verdict = %q, want clean", resp.Enrichments[0].Verdict)
		}
	})
}

func TestEnrichDomain(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"win": map[string]any{"eventdata": map[string]any{"queryName": "evil.example"}},
		},
	}

	t.Run("resolves and checks abuse", func(t *testing.T) {
		resolver := &stubResolver{ip: net.ParseIP("203.0.113.9")}
		abuse := &stubAbuseIPDB{report: domain.AbuseReport{IPAddress: "203.0.113.9", AbuseConfidenceScore: 90}}
		resp := newTestEnricher(t, &stubVirusTotal{}, abuse, resolver).Enrich(context.Background(), alert)

		if resolver.gotHost != "evil.example" {
			t.Errorf("resolver got %q", resolver.gotHost)
		}
		if abuse.gotIP != "203.0.113.9" {
			t.Errorf("abuse got %q", abuse.gotIP)
		}
		if resp.Enrichments[0].Verdict != domain.VerdictSuspicious {
			t.Errorf("verdict = %q, want suspicious", resp.Enrichments[0].Verdict)
		}
	})

	t.Run("resolution failure yields unknown", func(t *testing.T) {
		resolver := &stubResolver{err: context.DeadlineExceeded}
		resp := newTestEnricher(t, &stubVirusTotal{}, &stubAbuseIPDB{}, resolver).Enrich(context.Background(), alert)

		res := resp.Enrichments[0]
		if res.Verdict != domain.VerdictUnknown || !strings.Contains(res.Error, "resolve domain") {
			t.Errorf("unexpected result: %+v", res)
		}
	})
}

func TestEnrichUsesCache(t *testing.T) {
	vt := &stubVirusTotal{urlStats: domain.AnalysisStats{Malicious: 1}}
	alert := map[string]any{"data": map[string]any{"url": "http://evil.example/x"}}
	svc := newTestEnricher(t, vt, &stubAbuseIPDB{}, &stubResolver{})

	first := svc.Enrich(context.Background(), alert)
	second := svc.Enrich(context.Background(), alert)

	if first.Enrichments[0].Cached {
		t.Error("first lookup must not be served from cache")
	}
	if !second.Enrichments[0].Cached {
		t.Error("second lookup must be served from cache")
	}
	if vt.gotURL != "http://evil.example/x" || second.Summary.LookedUp != 1 {
		t.Errorf("unexpected state: vt=%q summary=%+v", vt.gotURL, second.Summary)
	}
}

func TestEnrichRateLimited(t *testing.T) {
	svc, err := usecase.NewEnrichmentService(usecase.EnrichmentDeps{
		VirusTotal:        &stubVirusTotal{urlStats: domain.AnalysisStats{Malicious: 1}},
		Abuse:             &stubAbuseIPDB{},
		Resolver:          &stubResolver{},
		Extractor:         usecase.NewIOCExtractor(10, nil),
		Cache:             usecase.NewVerdictCache(time.Hour),
		VirusTotalLimiter: ratelimit.New(1), // exhausted after the first IOC
		AbuseLimiter:      ratelimit.New(100000),
	})
	if err != nil {
		t.Fatalf("NewEnrichmentService() error = %v", err)
	}

	// Two URL IOCs, limiter burst of one: the second must be rate limited.
	alert := map[string]any{
		"data": map[string]any{
			"url":  "http://first.example/x",
			"data": map[string]any{"url": "http://second.example/y"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resp := svc.Enrich(ctx, alert)

	if len(resp.Enrichments) != 2 {
		t.Fatalf("got %d enrichments, want 2", len(resp.Enrichments))
	}
	second := resp.Enrichments[1]
	if second.Verdict != domain.VerdictUnknown || !strings.Contains(second.Error, "rate limited") {
		t.Errorf("second IOC should be rate limited, got %+v", second)
	}
	if resp.Summary.Failures != 1 || resp.Summary.Malicious != 1 {
		t.Errorf("unexpected summary: %+v", resp.Summary)
	}
}

func TestNewEnrichmentServiceValidatesDeps(t *testing.T) {
	if _, err := usecase.NewEnrichmentService(usecase.EnrichmentDeps{}); err == nil {
		t.Fatal("expected error for empty deps")
	}
}

func TestVerdictCacheExpiry(t *testing.T) {
	cache := usecase.NewVerdictCache(time.Nanosecond)
	cache.Put("url:x", domain.EnrichmentResult{Verdict: domain.VerdictClean})

	time.Sleep(time.Millisecond)
	if _, ok := cache.Get("url:x"); ok {
		t.Error("expired entry must not be returned")
	}
}
