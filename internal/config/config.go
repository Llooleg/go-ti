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
	"strings"
)

// Names of the required environment variables.
const (
	EnvVirusTotalAPIKey = "VTKEY"
	EnvAbuseIPDBAPIKey  = "IPABUSEKEY"
)

// Config holds the runtime configuration of the application.
type Config struct {
	VirusTotalAPIKey string
	AbuseIPDBAPIKey  string
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

	return cfg, nil
}
