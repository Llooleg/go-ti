package domain

import "testing"

func TestNewAnalysisStats(t *testing.T) {
	raw := map[string]int{
		"harmless":          80,
		"malicious":         2,
		"suspicious":        1,
		"undetected":        10,
		"timeout":           1,
		"confirmed-timeout": 2,
		"type-unsupported":  3,
	}

	stats := NewAnalysisStats(raw)

	if stats.Harmless != 80 || stats.Malicious != 2 || stats.Suspicious != 1 || stats.Undetected != 10 {
		t.Fatalf("unexpected named counters: %+v", stats)
	}
	if stats.Timeout != 3 {
		t.Errorf("Timeout = %d, want 3 (timeout + confirmed-timeout)", stats.Timeout)
	}
	if stats.Other["type-unsupported"] != 3 {
		t.Errorf("Other[type-unsupported] = %d, want 3", stats.Other["type-unsupported"])
	}
	if want := 80 + 2 + 1 + 10 + 3 + 3; stats.TotalEngines() != want {
		t.Errorf("TotalEngines() = %d, want %d", stats.TotalEngines(), want)
	}
}

func TestNewAnalysisStatsEmpty(t *testing.T) {
	stats := NewAnalysisStats(nil)
	if stats.TotalEngines() != 0 {
		t.Errorf("TotalEngines() = %d, want 0", stats.TotalEngines())
	}
	if stats.Other != nil {
		t.Errorf("Other = %v, want nil", stats.Other)
	}
}
