// Package config loads application configuration from the environment.
//
// The application intentionally never reads .env files (see AGENTS.MD).
// For local development, export the variables into your shell, e.g.:
//
//	set -a; source .env; set +a
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Names of the required environment variables.
const (
	EnvVirusTotalAPIKey = "VTKEY"
	EnvAbuseIPDBAPIKey  = "IPABUSEKEY"
)

// Names of the optional enrichment-related environment variables.
const (
	EnvVTRatePerMin     = "VT_RATE_PER_MIN"
	EnvAbuseRatePerMin  = "ABUSE_RATE_PER_MIN"
	EnvIOCCacheTTL      = "IOC_CACHE_TTL"
	EnvMaxIOCsPerAlert  = "MAX_IOCS_PER_ALERT"
	EnvDomainSkipSuffix = "DOMAIN_SKIP_SUFFIXES"
	EnvEnrichTimeout    = "ENRICH_TIMEOUT"
	EnvWebToken         = "GOTI_WEB_TOKEN"
)

// Default values for the optional settings.
const (
	DefaultVTRatePerMin    = 4 // VirusTotal public quota
	DefaultAbuseRatePerMin = 60
	DefaultIOCCacheTTL     = 24 * time.Hour
	DefaultMaxIOCsPerAlert = 10
	DefaultEnrichTimeout   = 15 * time.Second
)

// DefaultDomainSkipSuffixes lists domain suffixes never treated as IOCs.
func DefaultDomainSkipSuffixes() []string {
	return []string{".arpa", ".local", ".internal"}
}

// EnrichmentConfig groups the optional settings of the enrichment pipeline.
type EnrichmentConfig struct {
	VTRatePerMin       int
	AbuseRatePerMin    int
	IOCCacheTTL        time.Duration
	MaxIOCsPerAlert    int
	DomainSkipSuffixes []string
	EnrichTimeout      time.Duration
	WebToken           string
}

// Config holds the runtime configuration of the application.
type Config struct {
	VirusTotalAPIKey string
	AbuseIPDBAPIKey  string
	Enrichment       EnrichmentConfig
}

// Load reads the configuration from the process environment and validates it.
func Load() (Config, error) {
	cfg := Config{
		VirusTotalAPIKey: os.Getenv(EnvVirusTotalAPIKey),
		AbuseIPDBAPIKey:  os.Getenv(EnvAbuseIPDBAPIKey),
	}

	var missing []string
	if cfg.VirusTotalAPIKey == "" {
		missing = append(missing, EnvVirusTotalAPIKey)
	}
	if cfg.AbuseIPDBAPIKey == "" {
		missing = append(missing, EnvAbuseIPDBAPIKey)
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	enrichment, err := loadEnrichmentConfig()
	if err != nil {
		return Config{}, err
	}
	cfg.Enrichment = enrichment

	return cfg, nil
}

func loadEnrichmentConfig() (EnrichmentConfig, error) {
	cfg := EnrichmentConfig{
		VTRatePerMin:       DefaultVTRatePerMin,
		AbuseRatePerMin:    DefaultAbuseRatePerMin,
		IOCCacheTTL:        DefaultIOCCacheTTL,
		MaxIOCsPerAlert:    DefaultMaxIOCsPerAlert,
		DomainSkipSuffixes: DefaultDomainSkipSuffixes(),
		EnrichTimeout:      DefaultEnrichTimeout,
		WebToken:           os.Getenv(EnvWebToken),
	}

	var err error
	if cfg.VTRatePerMin, err = envInt(EnvVTRatePerMin, cfg.VTRatePerMin); err != nil {
		return EnrichmentConfig{}, err
	}
	if cfg.AbuseRatePerMin, err = envInt(EnvAbuseRatePerMin, cfg.AbuseRatePerMin); err != nil {
		return EnrichmentConfig{}, err
	}
	if cfg.MaxIOCsPerAlert, err = envInt(EnvMaxIOCsPerAlert, cfg.MaxIOCsPerAlert); err != nil {
		return EnrichmentConfig{}, err
	}
	if cfg.IOCCacheTTL, err = envDuration(EnvIOCCacheTTL, cfg.IOCCacheTTL); err != nil {
		return EnrichmentConfig{}, err
	}
	if cfg.EnrichTimeout, err = envDuration(EnvEnrichTimeout, cfg.EnrichTimeout); err != nil {
		return EnrichmentConfig{}, err
	}
	if raw, ok := os.LookupEnv(EnvDomainSkipSuffix); ok {
		cfg.DomainSkipSuffixes = parseSuffixList(raw)
	}

	return cfg, nil
}

func envInt(name string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 1 {
		return 0, fmt.Errorf("invalid value for %s: %q", name, raw)
	}
	return value, nil
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid value for %s: %q", name, raw)
	}
	return value, nil
}

func parseSuffixList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if !strings.HasPrefix(part, ".") {
			part = "." + part
		}
		out = append(out, part)
	}
	return out
}
