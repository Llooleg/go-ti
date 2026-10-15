package usecase

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go-ti/internal/domain"
	"go-ti/pkg/ratelimit"
)

// EnrichmentDeps groups the collaborators of EnrichmentService.
type EnrichmentDeps struct {
	VirusTotal        VirusTotal
	Abuse             AbuseIPDB
	Resolver          Resolver
	Extractor         *IOCExtractor
	Cache             *VerdictCache
	VirusTotalLimiter *ratelimit.Limiter
	AbuseLimiter      *ratelimit.Limiter
}

// EnrichmentService enriches Wazuh alerts with threat-intelligence verdicts.
// It orchestrates IOC extraction, caching and rate-limited lookups.
type EnrichmentService struct {
	deps EnrichmentDeps
}

// NewEnrichmentService wires the service with its dependencies and validates
// that none of them are missing.
func NewEnrichmentService(deps EnrichmentDeps) (*EnrichmentService, error) {
	switch {
	case deps.VirusTotal == nil:
		return nil, errors.New("enrichment: VirusTotal dependency is nil")
	case deps.Abuse == nil:
		return nil, errors.New("enrichment: AbuseIPDB dependency is nil")
	case deps.Resolver == nil:
		return nil, errors.New("enrichment: Resolver dependency is nil")
	case deps.Extractor == nil:
		return nil, errors.New("enrichment: Extractor dependency is nil")
	case deps.Cache == nil:
		return nil, errors.New("enrichment: Cache dependency is nil")
	case deps.VirusTotalLimiter == nil:
		return nil, errors.New("enrichment: VirusTotalLimiter dependency is nil")
	case deps.AbuseLimiter == nil:
		return nil, errors.New("enrichment: AbuseLimiter dependency is nil")
	}
	return &EnrichmentService{deps: deps}, nil
}

// Enrich extracts IOCs from the alert and analyzes every one of them.
// Partial failures are reported per IOC (verdict "unknown" + error), the
// response itself always succeeds.
func (s *EnrichmentService) Enrich(ctx context.Context, alert map[string]any) domain.EnrichmentResponse {
	iocs := s.deps.Extractor.Extract(alert)

	response := domain.EnrichmentResponse{
		Enrichments: make([]domain.EnrichmentResult, 0, len(iocs)),
	}
	response.Summary.IOCsFound = len(iocs)

	for _, ioc := range iocs {
		result := s.enrichIOC(ctx, ioc)

		response.Summary.LookedUp++
		switch result.Verdict {
		case domain.VerdictMalicious:
			response.Summary.Malicious++
		case domain.VerdictSuspicious:
			response.Summary.Suspicious++
		}
		if result.Error != "" {
			response.Summary.Failures++
		}
		response.Enrichments = append(response.Enrichments, result)
	}

	return response
}

func (s *EnrichmentService) enrichIOC(ctx context.Context, ioc domain.IOC) domain.EnrichmentResult {
	if cached, ok := s.deps.Cache.Get(ioc.Key()); ok {
		cached.Cached = true
		cached.IOC = ioc
		return cached
	}

	var (
		result domain.EnrichmentResult
		err    error
	)
	result.IOC = ioc

	switch ioc.Type {
	case domain.IOCTypeURL:
		result.Stats, err = s.lookupURL(ctx, ioc.Value)
	case domain.IOCTypeFileHash:
		result.Stats, err = s.lookupHash(ctx, ioc.Algo, ioc.Value)
	case domain.IOCTypeIP:
		result.Abuse, err = s.lookupIP(ctx, ioc.Value)
	case domain.IOCTypeDomain:
		result.Abuse, err = s.lookupDomain(ctx, ioc.Value)
	}

	if err != nil {
		result.Verdict = domain.VerdictUnknown
		result.Error = err.Error()
		return result // failures are not cached so the next alert can retry
	}

	result.Verdict = computeVerdict(result.Stats, result.Abuse)
	s.deps.Cache.Put(ioc.Key(), result)

	return result
}

func (s *EnrichmentService) lookupURL(ctx context.Context, rawURL string) (*domain.AnalysisStats, error) {
	if err := s.deps.VirusTotalLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limited: %w", err)
	}
	stats, err := s.deps.VirusTotal.URLStats(ctx, rawURL)
	if err != nil {
		return nil, fmt.Errorf("virustotal url stats: %w", err)
	}
	return &stats, nil
}

func (s *EnrichmentService) lookupHash(ctx context.Context, algo, hash string) (*domain.AnalysisStats, error) {
	if err := s.deps.VirusTotalLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limited: %w", err)
	}
	stats, err := s.deps.VirusTotal.HashStats(ctx, algo, hash)
	if err != nil {
		return nil, fmt.Errorf("virustotal hash stats: %w", err)
	}
	return &stats, nil
}

func (s *EnrichmentService) lookupIP(ctx context.Context, ip string) (*domain.AbuseReport, error) {
	if err := s.deps.AbuseLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limited: %w", err)
	}
	report, err := s.deps.Abuse.CheckIP(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb check: %w", err)
	}
	return &report, nil
}

func (s *EnrichmentService) lookupDomain(ctx context.Context, domainName string) (*domain.AbuseReport, error) {
	ip, err := s.deps.Resolver.LookupIPv4(ctx, domainName)
	if err != nil {
		return nil, fmt.Errorf("resolve domain: %w", err)
	}
	return s.lookupIP(ctx, ip.String())
}

// computeVerdict aggregates VirusTotal stats and the AbuseIPDB report into a
// single verdict:
//
//	malicious: at least one VT engine flagged the IOC as malicious
//	suspicious: at least one VT "suspicious" or AbuseIPDB confidence >= 50
//	clean:      some data was collected and nothing above fired
//	unknown:    no data at all
func computeVerdict(stats *domain.AnalysisStats, abuse *domain.AbuseReport) domain.EnrichmentVerdict {
	if stats != nil && stats.Malicious >= 1 {
		return domain.VerdictMalicious
	}
	if (stats != nil && stats.Suspicious >= 1) || (abuse != nil && abuse.AbuseConfidenceScore >= 50) {
		return domain.VerdictSuspicious
	}
	if stats != nil || abuse != nil {
		return domain.VerdictClean
	}
	return domain.VerdictUnknown
}

// VerdictCache is an in-memory TTL cache for enrichment results.
// It is safe for concurrent use.
type VerdictCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]verdictCacheEntry
}

type verdictCacheEntry struct {
	result  domain.EnrichmentResult
	expires time.Time
}

// NewVerdictCache creates a cache with the given TTL.
func NewVerdictCache(ttl time.Duration) *VerdictCache {
	return &VerdictCache{
		ttl:     ttl,
		entries: make(map[string]verdictCacheEntry),
	}
}

// Get returns a cached result if present and not expired. The Cached flag of
// the returned copy is left untouched for the caller to set.
func (c *VerdictCache) Get(key string) (domain.EnrichmentResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return domain.EnrichmentResult{}, false
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, key)
		return domain.EnrichmentResult{}, false
	}
	return entry.result, true
}

// Put stores a successful result under key.
func (c *VerdictCache) Put(key string, result domain.EnrichmentResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = verdictCacheEntry{
		result:  result,
		expires: time.Now().Add(c.ttl),
	}
}
