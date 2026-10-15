package usecase_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"go-ti/internal/domain"
	"go-ti/internal/usecase"
)

type stubVirusTotal struct {
	urlStats  domain.AnalysisStats
	urlErr    error
	fileStats domain.AnalysisStats
	fileErr   error

	gotURL     string
	gotFileSHA string
}

func (s *stubVirusTotal) URLStats(_ context.Context, rawURL string) (domain.AnalysisStats, error) {
	s.gotURL = rawURL
	return s.urlStats, s.urlErr
}

func (s *stubVirusTotal) FileStats(_ context.Context, sha256 string) (domain.AnalysisStats, error) {
	s.gotFileSHA = sha256
	return s.fileStats, s.fileErr
}

type stubAbuseIPDB struct {
	report domain.AbuseReport
	err    error

	gotIP string
}

func (s *stubAbuseIPDB) CheckIP(_ context.Context, ip string) (domain.AbuseReport, error) {
	s.gotIP = ip
	return s.report, s.err
}

type stubResolver struct {
	ip  net.IP
	err error

	gotHost string
}

func (s *stubResolver) LookupIPv4(_ context.Context, host string) (net.IP, error) {
	s.gotHost = host
	return s.ip, s.err
}

type stubHasher struct {
	sum string
	err error

	gotPath string
}

func (s *stubHasher) FileSHA256(path string) (string, error) {
	s.gotPath = path
	return s.sum, s.err
}

func newService(vt usecase.VirusTotal, abuse usecase.AbuseIPDB, resolver usecase.Resolver, hasher usecase.FileHasher) *usecase.AnalysisService {
	return usecase.NewAnalysisService(vt, abuse, resolver, hasher)
}

func TestAnalyzeLink(t *testing.T) {
	vt := &stubVirusTotal{urlStats: domain.AnalysisStats{Malicious: 2, Harmless: 80}}
	resolver := &stubResolver{ip: net.ParseIP("93.184.216.34")}
	abuse := &stubAbuseIPDB{report: domain.AbuseReport{IPAddress: "93.184.216.34", AbuseConfidenceScore: 5}}
	hasher := &stubHasher{}

	result, err := newService(vt, abuse, resolver, hasher).Analyze(context.Background(), " https://example.com ")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Kind != domain.InputKindLink {
		t.Errorf("Kind = %q, want %q", result.Kind, domain.InputKindLink)
	}
	if vt.gotURL != "https://example.com" {
		t.Errorf("VirusTotal got url %q, want trimmed %q", vt.gotURL, "https://example.com")
	}
	if resolver.gotHost != "example.com" {
		t.Errorf("Resolver got host %q, want %q", resolver.gotHost, "example.com")
	}
	if resolver.gotHost == "" || abuse.gotIP != "93.184.216.34" {
		t.Errorf("AbuseIPDB got ip %q, want %q", abuse.gotIP, "93.184.216.34")
	}
	if result.ResolvedIP != "93.184.216.34" {
		t.Errorf("ResolvedIP = %q, want %q", result.ResolvedIP, "93.184.216.34")
	}
	if result.Abuse == nil || result.Abuse.AbuseConfidenceScore != 5 {
		t.Errorf("unexpected abuse report: %+v", result.Abuse)
	}
	if hasher.gotPath != "" {
		t.Errorf("file hasher must not be called for links, got path %q", hasher.gotPath)
	}
}

func TestAnalyzeFile(t *testing.T) {
	vt := &stubVirusTotal{fileStats: domain.AnalysisStats{Malicious: 1, Undetected: 60}}
	resolver := &stubResolver{ip: net.ParseIP("93.184.216.34")}
	abuse := &stubAbuseIPDB{}
	hasher := &stubHasher{sum: "deadbeef"}

	result, err := newService(vt, abuse, resolver, hasher).Analyze(context.Background(), "/tmp/some file.bin")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Kind != domain.InputKindFile {
		t.Errorf("Kind = %q, want %q", result.Kind, domain.InputKindFile)
	}
	if hasher.gotPath != "/tmp/some file.bin" {
		t.Errorf("hasher got path %q, want %q", hasher.gotPath, "/tmp/some file.bin")
	}
	if vt.gotFileSHA != "deadbeef" {
		t.Errorf("VirusTotal got sha %q, want %q", vt.gotFileSHA, "deadbeef")
	}
	if result.Stats.Malicious != 1 || result.Stats.Undetected != 60 {
		t.Errorf("unexpected stats: %+v", result.Stats)
	}
	if result.Abuse != nil || result.ResolvedIP != "" {
		t.Errorf("file analysis must not fill link-only fields: %+v", result)
	}
}

func TestAnalyzeEmptyInput(t *testing.T) {
	_, err := newService(&stubVirusTotal{}, &stubAbuseIPDB{}, &stubResolver{}, &stubHasher{}).
		Analyze(context.Background(), "   ")
	if !errors.Is(err, usecase.ErrEmptyInput) {
		t.Errorf("Analyze() error = %v, want usecase.ErrEmptyInput", err)
	}
}

func TestAnalyzeLinkPartialResultOnError(t *testing.T) {
	vt := &stubVirusTotal{urlStats: domain.AnalysisStats{Harmless: 42}}
	resolver := &stubResolver{err: errors.New("dns is down")}
	abuse := &stubAbuseIPDB{}
	hasher := &stubHasher{}

	result, err := newService(vt, abuse, resolver, hasher).Analyze(context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("Analyze() expected error when DNS fails")
	}
	if result.Stats.Harmless != 42 {
		t.Errorf("partial result should keep collected stats, got %+v", result.Stats)
	}
	if result.Abuse != nil {
		t.Errorf("Abuse should be nil, got %+v", result.Abuse)
	}
	if abuse.gotIP != "" {
		t.Errorf("AbuseIPDB must not be called when DNS fails, got ip %q", abuse.gotIP)
	}
}
