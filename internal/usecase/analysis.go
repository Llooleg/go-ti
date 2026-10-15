// Package usecase contains the business logic and orchestration rules.
package usecase

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"go-ti/internal/domain"
	"go-ti/pkg/inputparse"
)

// ErrEmptyInput is returned when the user provides no input at all.
var ErrEmptyInput = errors.New("usecase: empty input")

// VirusTotal provides VirusTotal analysis stats. Implemented by repository adapters.
type VirusTotal interface {
	URLStats(ctx context.Context, rawURL string) (domain.AnalysisStats, error)
	FileStats(ctx context.Context, sha256 string) (domain.AnalysisStats, error)
}

// AbuseIPDB provides IP abuse reports. Implemented by repository adapters.
type AbuseIPDB interface {
	CheckIP(ctx context.Context, ip string) (domain.AbuseReport, error)
}

// Resolver resolves hostnames to IPv4 addresses. Implemented by repository adapters.
type Resolver interface {
	LookupIPv4(ctx context.Context, host string) (net.IP, error)
}

// FileHasher computes file digests. Implemented by pkg/checksum.
type FileHasher interface {
	FileSHA256(path string) (string, error)
}

// AnalysisService orchestrates threat intelligence analysis of links and files.
type AnalysisService struct {
	vt       VirusTotal
	abuse    AbuseIPDB
	resolver Resolver
	hasher   FileHasher
}

// NewAnalysisService wires the service with its dependencies.
func NewAnalysisService(vt VirusTotal, abuse AbuseIPDB, resolver Resolver, hasher FileHasher) *AnalysisService {
	return &AnalysisService{
		vt:       vt,
		abuse:    abuse,
		resolver: resolver,
		hasher:   hasher,
	}
}

// Analyze classifies the input (link or file path) and produces a report.
//
// For links the service queries VirusTotal, resolves the host to an IPv4
// address and queries AbuseIPDB. If a later stage fails, the partially
// filled result is returned together with the error so callers can still
// show whatever was collected before the failure.
func (s *AnalysisService) Analyze(ctx context.Context, input string) (domain.AnalysisResult, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return domain.AnalysisResult{}, ErrEmptyInput
	}

	if inputparse.IsLink(trimmed) {
		return s.analyzeLink(ctx, trimmed)
	}
	return s.analyzeFile(ctx, trimmed)
}

func (s *AnalysisService) analyzeLink(ctx context.Context, link string) (domain.AnalysisResult, error) {
	result := domain.AnalysisResult{
		Input: link,
		Kind:  domain.InputKindLink,
	}

	stats, err := s.vt.URLStats(ctx, link)
	if err != nil {
		return result, fmt.Errorf("virustotal url stats: %w", err)
	}
	result.Stats = stats

	parsed, err := url.Parse(link)
	if err != nil {
		return result, fmt.Errorf("parse url: %w", err)
	}

	ip, err := s.resolver.LookupIPv4(ctx, parsed.Hostname())
	if err != nil {
		return result, fmt.Errorf("resolve host: %w", err)
	}
	result.ResolvedIP = ip.String()

	report, err := s.abuse.CheckIP(ctx, ip.String())
	if err != nil {
		return result, fmt.Errorf("abuseipdb check: %w", err)
	}
	result.Abuse = &report

	return result, nil
}

func (s *AnalysisService) analyzeFile(ctx context.Context, path string) (domain.AnalysisResult, error) {
	result := domain.AnalysisResult{
		Input: path,
		Kind:  domain.InputKindFile,
	}

	sha256sum, err := s.hasher.FileSHA256(path)
	if err != nil {
		return result, fmt.Errorf("hash file: %w", err)
	}

	stats, err := s.vt.FileStats(ctx, sha256sum)
	if err != nil {
		return result, fmt.Errorf("virustotal file stats: %w", err)
	}
	result.Stats = stats

	return result, nil
}
