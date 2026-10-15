// Package cli is the console delivery layer of the application.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go-ti/internal/domain"
)

// ErrNoInput is returned when the user provides no target to analyze.
var ErrNoInput = errors.New("cli: no input provided")

// AnalysisService is the business capability exposed to this transport layer.
type AnalysisService interface {
	Analyze(ctx context.Context, input string) (domain.AnalysisResult, error)
}

// Handler reads user input and renders analysis reports.
type Handler struct {
	service AnalysisService
	in      io.Reader
	out     io.Writer

	// printErr records the first write error so that every report line can
	// be emitted without checking each fmt call at the call site.
	printErr error
}

// New creates a console handler around the given analysis service.
func New(service AnalysisService, in io.Reader, out io.Writer) *Handler {
	return &Handler{service: service, in: in, out: out}
}

// Run analyzes the target taken from args, or interactively from stdin when
// no args are given, and prints the resulting report.
func (h *Handler) Run(ctx context.Context, args []string) error {
	input := strings.TrimSpace(strings.Join(args, " "))
	if input == "" {
		prompted, err := h.prompt()
		if err != nil {
			return err
		}
		input = prompted
	}

	result, err := h.service.Analyze(ctx, input)
	if result.Input != "" {
		// Show whatever was collected even when the analysis failed midway.
		h.printResult(result)
	}
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	return h.printErr
}

func (h *Handler) prompt() (string, error) {
	h.printf("Enter a link or file path here: ")

	line, err := bufio.NewReader(h.in).ReadString('\n')
	input := strings.TrimSpace(line)
	if input == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read input: %w", err)
		}
		return "", ErrNoInput
	}
	return input, nil
}

func (h *Handler) printResult(result domain.AnalysisResult) {
	if result.Kind == domain.InputKindLink {
		h.println("=== Link analysis ===")
		h.printf("URL: %s\n", result.Input)
		if result.ResolvedIP != "" {
			h.printf("Resolved IPv4: %s\n", result.ResolvedIP)
		}
	} else {
		h.println("=== File analysis ===")
		h.printf("Path: %s\n", result.Input)
	}

	h.printStats(result.Stats)
	if result.Abuse != nil {
		h.printAbuseReport(*result.Abuse)
	}
}

func (h *Handler) printStats(s domain.AnalysisStats) {
	h.printf("\nVirusTotal analysis stats (%d engines reported):\n", s.TotalEngines())
	h.printf("  malicious:  %d\n", s.Malicious)
	h.printf("  suspicious: %d\n", s.Suspicious)
	h.printf("  harmless:   %d\n", s.Harmless)
	h.printf("  undetected: %d\n", s.Undetected)
	h.printf("  timeout:    %d\n", s.Timeout)
	for _, key := range sortedKeys(s.Other) {
		h.printf("  %s: %d\n", key, s.Other[key])
	}
}

func (h *Handler) printAbuseReport(r domain.AbuseReport) {
	h.printf("\nAbuseIPDB report for %s:\n", r.IPAddress)
	h.printf("  abuse confidence: %d%%\n", r.AbuseConfidenceScore)
	h.printf("  country:          %s\n", orUnknown(r.CountryCode))
	h.printf("  ISP:              %s\n", orUnknown(r.ISP))
	h.printf("  usage type:       %s\n", orUnknown(r.UsageType))
	h.printf("  domain:           %s\n", orUnknown(r.Domain))
	h.printf("  hostnames:        %s\n", orUnknown(strings.Join(r.Hostnames, ", ")))
	h.printf("  total reports:    %d\n", r.TotalReports)
	h.printf("  distinct users:   %d\n", r.NumDistinctUsers)
	h.printf("  last reported at: %s\n", orUnknown(r.LastReportedAt))
	h.printf("  whitelisted:      %t\n", r.IsWhitelisted)
	h.printf("  public:           %t (IPv%d)\n", r.IsPublic, r.IPVersion)
}

func (h *Handler) printf(format string, args ...any) {
	h.write(fmt.Sprintf(format, args...))
}

func (h *Handler) println(s string) {
	h.write(s + "\n")
}

func (h *Handler) write(s string) {
	if h.printErr != nil {
		return
	}
	if _, err := io.WriteString(h.out, s); err != nil {
		h.printErr = fmt.Errorf("write report: %w", err)
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
