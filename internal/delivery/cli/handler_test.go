package cli_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"go-ti/internal/delivery/cli"
	"go-ti/internal/domain"
	"go-ti/internal/usecase"
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

func sampleLinkResult() domain.AnalysisResult {
	return domain.AnalysisResult{
		Input:      "https://example.com",
		Kind:       domain.InputKindLink,
		ResolvedIP: "93.184.216.34",
		Stats:      domain.AnalysisStats{Malicious: 2, Suspicious: 1, Harmless: 80},
		Abuse: &domain.AbuseReport{
			IPAddress:            "93.184.216.34",
			IsPublic:             true,
			IPVersion:            4,
			AbuseConfidenceScore: 5,
			CountryCode:          "US",
			ISP:                  "Example ISP",
			TotalReports:         3,
			NumDistinctUsers:     2,
			LastReportedAt:       "2024-01-01T00:00:00+00:00",
		},
	}
}

func TestRunWithArg(t *testing.T) {
	svc := &stubService{result: sampleLinkResult()}
	var out bytes.Buffer

	handler := cli.New(svc, strings.NewReader(""), &out)
	if err := handler.Run(context.Background(), []string{"https://example.com"}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if svc.gotInpt != "https://example.com" {
		t.Errorf("service got input %q", svc.gotInpt)
	}

	report := out.String()
	for _, want := range []string{
		"=== Link analysis ===",
		"URL: https://example.com",
		"Resolved IPv4: 93.184.216.34",
		"VirusTotal analysis stats",
		"malicious:  2",
		"harmless:   80",
		"AbuseIPDB report for 93.184.216.34",
		"abuse confidence: 5%",
		"country:          US",
		"total reports:    3",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\nreport:\n%s", want, report)
		}
	}
	if strings.Contains(report, "Enter a link") {
		t.Error("prompt must not be shown when args are given")
	}
}

func TestRunWithPrompt(t *testing.T) {
	svc := &stubService{result: sampleLinkResult()}
	var out bytes.Buffer

	handler := cli.New(svc, strings.NewReader("https://example.com\n"), &out)
	if err := handler.Run(context.Background(), nil); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(out.String(), "Enter a link or file path here: ") {
		t.Error("expected interactive prompt in output")
	}
	if svc.gotInpt != "https://example.com" {
		t.Errorf("service got input %q", svc.gotInpt)
	}
}

func TestRunFileReport(t *testing.T) {
	svc := &stubService{result: domain.AnalysisResult{
		Input: "/tmp/warez.exe",
		Kind:  domain.InputKindFile,
		Stats: domain.AnalysisStats{Malicious: 40, Undetected: 20},
	}}
	var out bytes.Buffer

	handler := cli.New(svc, strings.NewReader(""), &out)
	if err := handler.Run(context.Background(), []string{"/tmp/warez.exe"}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	report := out.String()
	if !strings.Contains(report, "=== File analysis ===") || !strings.Contains(report, "Path: /tmp/warez.exe") {
		t.Errorf("unexpected file report:\n%s", report)
	}
}

func TestRunEmptyInput(t *testing.T) {
	svc := &stubService{}
	var out bytes.Buffer

	handler := cli.New(svc, strings.NewReader("\n"), &out)
	err := handler.Run(context.Background(), nil)
	if !errors.Is(err, cli.ErrNoInput) {
		t.Errorf("Run() error = %v, want cli.ErrNoInput", err)
	}
}

func TestRunPrintsPartialResultOnError(t *testing.T) {
	svc := &stubService{
		result: sampleLinkResult(),
		err:    errors.Join(errors.New("abuseipdb check: boom")),
	}
	var out bytes.Buffer

	handler := cli.New(svc, strings.NewReader(""), &out)
	if err := handler.Run(context.Background(), []string{"https://example.com"}); err == nil {
		t.Fatal("Run() expected error")
	}
	if !strings.Contains(out.String(), "=== Link analysis ===") {
		t.Errorf("partial result must still be printed, got:\n%s", out.String())
	}
}

// Compile-time check that *usecase.AnalysisService satisfies the transport
// layer's consumer-side interface.
var _ cli.AnalysisService = (*usecase.AnalysisService)(nil)
