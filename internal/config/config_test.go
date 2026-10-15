package config_test

import (
	"testing"

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
