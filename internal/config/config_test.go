package config_test

import (
	"reflect"
	"testing"
	"time"

	"go-ti/internal/config"
)

func TestLoad(t *testing.T) {
	t.Run("all variables set", func(t *testing.T) {
		t.Setenv("VTKEY", "vt-secret")
		t.Setenv("IPABUSEKEY", "abuse-secret")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.VirusTotalAPIKey != "vt-secret" || cfg.AbuseIPDBAPIKey != "abuse-secret" {
			t.Errorf("unexpected config: %+v", cfg)
		}
	})

	t.Run("missing variables", func(t *testing.T) {
		t.Setenv("VTKEY", "")
		t.Setenv("IPABUSEKEY", "")

		_, err := config.Load()
		if err == nil {
			t.Fatal("Load() expected error for missing variables")
		}
	})
}

func TestLoadEnrichmentDefaults(t *testing.T) {
	t.Setenv("VTKEY", "k1")
	t.Setenv("IPABUSEKEY", "k2")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	e := cfg.Enrichment
	if e.VTRatePerMin != 4 || e.AbuseRatePerMin != 60 || e.MaxIOCsPerAlert != 10 {
		t.Errorf("unexpected rate defaults: %+v", e)
	}
	if e.IOCCacheTTL != 24*time.Hour || e.EnrichTimeout != 15*time.Second {
		t.Errorf("unexpected duration defaults: %+v", e)
	}
	if len(e.DomainSkipSuffixes) != 3 || e.DomainSkipSuffixes[0] != ".arpa" {
		t.Errorf("unexpected suffix defaults: %v", e.DomainSkipSuffixes)
	}
	if e.WebToken != "" {
		t.Errorf("WebToken = %q, want empty by default", e.WebToken)
	}
}

func TestLoadEnrichmentOverrides(t *testing.T) {
	t.Setenv("VTKEY", "k1")
	t.Setenv("IPABUSEKEY", "k2")
	t.Setenv("VT_RATE_PER_MIN", "10")
	t.Setenv("IOC_CACHE_TTL", "1h30m")
	t.Setenv("MAX_IOCS_PER_ALERT", "25")
	t.Setenv("DOMAIN_SKIP_SUFFIXES", "internal, .corp ,lan")
	t.Setenv("GOTI_WEB_TOKEN", "secret")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	e := cfg.Enrichment
	if e.VTRatePerMin != 10 || e.MaxIOCsPerAlert != 25 || e.IOCCacheTTL != 90*time.Minute {
		t.Errorf("unexpected overrides: %+v", e)
	}
	if e.WebToken != "secret" {
		t.Errorf("WebToken = %q", e.WebToken)
	}
	want := []string{".internal", ".corp", ".lan"}
	if !reflect.DeepEqual(e.DomainSkipSuffixes, want) {
		t.Errorf("suffixes = %v, want %v", e.DomainSkipSuffixes, want)
	}
}

func TestLoadEnrichmentInvalidValues(t *testing.T) {
	t.Setenv("VTKEY", "k1")
	t.Setenv("IPABUSEKEY", "k2")

	t.Setenv("VT_RATE_PER_MIN", "not-a-number")
	if _, err := config.Load(); err == nil {
		t.Error("invalid VT_RATE_PER_MIN must fail")
	}

	t.Setenv("VT_RATE_PER_MIN", "")
	t.Setenv("IOC_CACHE_TTL", "nope")
	if _, err := config.Load(); err == nil {
		t.Error("invalid IOC_CACHE_TTL must fail")
	}
}
