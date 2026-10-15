package usecase

import (
	"net"
	"strings"

	"go-ti/internal/domain"
	"go-ti/pkg/inputparse"
)

// defaultDomainSkipSuffixes are domain suffixes never reported as IOCs.
var defaultDomainSkipSuffixes = []string{".arpa", ".local", ".internal"}

// IOCExtractor pulls indicators of compromise out of Wazuh alert payloads.
// It is tolerant by design: unknown alert layouts simply yield fewer IOCs,
// never errors.
type IOCExtractor struct {
	maxIOCs      int
	skipSuffixes []string
}

// NewIOCExtractor creates an extractor bounded by maxIOCs per alert.
// Empty skipSuffixes falls back to the default infrastructure suffix list.
func NewIOCExtractor(maxIOCs int, skipSuffixes []string) *IOCExtractor {
	if maxIOCs < 1 {
		maxIOCs = 1
	}
	if len(skipSuffixes) == 0 {
		skipSuffixes = defaultDomainSkipSuffixes
	}
	normalized := make([]string, 0, len(skipSuffixes))
	for _, s := range skipSuffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		normalized = append(normalized, s)
	}
	return &IOCExtractor{maxIOCs: maxIOCs, skipSuffixes: normalized}
}

// Extract returns the deduplicated IOCs found in the alert, capped at the
// configured maximum. Extraction order is deterministic: hashes, urls,
// domains, ips.
func (e *IOCExtractor) Extract(alert map[string]any) []domain.IOC {
	seen := make(map[string]bool)
	iocs := make([]domain.IOC, 0)

	add := func(candidate func() (domain.IOC, bool)) {
		if len(iocs) >= e.maxIOCs {
			return
		}
		if ioc, ok := candidate(); ok && !seen[ioc.Key()] {
			seen[ioc.Key()] = true
			iocs = append(iocs, ioc)
		}
	}

	// File hashes: FIM (syscheck).
	for _, field := range []string{"sha256_after", "sha1_after", "md5_after"} {
		if raw, ok := fieldString(alert, "data", "syscheck", field); ok {
			add(func() (domain.IOC, bool) { return newHashIOC(raw) })
		}
	}

	// File hashes: Sysmon Hashes string ("SHA256=..,MD5=..").
	if raw, ok := fieldString(alert, "data", "win", "eventdata", "hashes"); ok {
		for _, pair := range parseSysmonHashes(raw) {
			algo, value := pair.algo, pair.value
			add(func() (domain.IOC, bool) {
				return domain.IOC{Type: domain.IOCTypeFileHash, Value: value, Algo: algo}, true
			})
		}
	}

	// URLs.
	for _, path := range [][]string{
		{"data", "url"},
		{"data", "data", "url"},
	} {
		if raw, ok := fieldString(alert, path...); ok {
			value := raw
			add(func() (domain.IOC, bool) { return newURLIOC(value) })
		}
	}

	// Domains: Suricata/Snort DNS events.
	if queries, ok := fieldAny(alert, "data", "dns", "queries").([]any); ok {
		for _, q := range queries {
			qm, ok := q.(map[string]any)
			if !ok {
				continue
			}
			name, ok := qm["name"].(string)
			if !ok {
				continue
			}
			value := name
			add(func() (domain.IOC, bool) { return e.newDomainIOC(value) })
		}
	}
	if raw, ok := fieldString(alert, "data", "dns", "rrname"); ok {
		value := raw
		add(func() (domain.IOC, bool) { return e.newDomainIOC(value) })
	}
	// Domains: Sysmon EventID 22 (DNS query).
	if raw, ok := fieldString(alert, "data", "win", "eventdata", "queryName"); ok {
		value := raw
		add(func() (domain.IOC, bool) { return e.newDomainIOC(value) })
	}

	// IP addresses.
	for _, path := range [][]string{
		{"data", "srcip"},
		{"data", "dstip"},
		{"srcip"},
		{"dstip"},
	} {
		if raw, ok := fieldString(alert, path...); ok {
			value := raw
			add(func() (domain.IOC, bool) { return newIPIOC(value) })
		}
	}

	return iocs
}

// newHashIOC validates a bare hash string and maps its length to an algorithm.
func newHashIOC(raw string) (domain.IOC, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if !isHex(value) {
		return domain.IOC{}, false
	}
	var algo string
	switch len(value) {
	case 32:
		algo = domain.HashAlgoMD5
	case 40:
		algo = domain.HashAlgoSHA1
	case 64:
		algo = domain.HashAlgoSHA256
	default:
		return domain.IOC{}, false
	}
	return domain.IOC{Type: domain.IOCTypeFileHash, Value: value, Algo: algo}, true
}

func newURLIOC(raw string) (domain.IOC, bool) {
	value := strings.TrimSpace(raw)
	if !inputparse.IsLink(value) {
		return domain.IOC{}, false
	}
	return domain.IOC{Type: domain.IOCTypeURL, Value: value}, true
}

func (e *IOCExtractor) newDomainIOC(raw string) (domain.IOC, bool) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if !isValidDomain(value) {
		return domain.IOC{}, false
	}
	for _, suffix := range e.skipSuffixes {
		if strings.HasSuffix(value, suffix) {
			return domain.IOC{}, false
		}
	}
	return domain.IOC{Type: domain.IOCTypeDomain, Value: value}, true
}

func newIPIOC(raw string) (domain.IOC, bool) {
	value := strings.TrimSpace(raw)
	ip := net.ParseIP(value)
	if ip == nil || !isPublicIP(ip) {
		return domain.IOC{}, false
	}
	return domain.IOC{Type: domain.IOCTypeIP, Value: value}, true
}

type sysmonHash struct {
	algo  string
	value string
}

// parseSysmonHashes parses strings like "SHA256=ABC...,MD5=DEF...".
// Non-file digests (e.g. IMPHASH) are ignored.
func parseSysmonHashes(raw string) []sysmonHash {
	var out []sysmonHash
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		var algo string
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "MD5":
			algo = domain.HashAlgoMD5
		case "SHA1":
			algo = domain.HashAlgoSHA1
		case "SHA256":
			algo = domain.HashAlgoSHA256
		default:
			continue
		}
		ioc, ok := newHashIOC(value)
		if ok && ioc.Algo == algo {
			out = append(out, sysmonHash{algo: algo, value: ioc.Value})
		}
	}
	return out
}

// isValidDomain reports whether s is a syntactically valid hostname with an
// alphabetic TLD (IP literals are rejected).
func isValidDomain(s string) bool {
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for i, label := range labels {
		if len(label) == 0 || len(label) > 63 ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' {
				return false
			}
		}
		if i == len(labels)-1 { // TLD: letters only, at least two.
			if len(label) < 2 {
				return false
			}
			for _, r := range label {
				if r < 'a' || r > 'z' {
					return false
				}
			}
		}
	}
	return true
}

// isPublicIP reports whether the IP is worth reporting as an IOC
// (private, loopback, link-local, multicast and unspecified addresses are not).
func isPublicIP(ip net.IP) bool {
	return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified())
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// fieldAny walks the alert by path segments and returns the value found.
func fieldAny(alert map[string]any, path ...string) any {
	var current any = alert
	for _, segment := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[segment]
		if !ok {
			return nil
		}
	}
	return current
}

func fieldString(alert map[string]any, path ...string) (string, bool) {
	s, ok := fieldAny(alert, path...).(string)
	return s, ok
}
