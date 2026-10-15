package domain

// IOCType classifies an indicator of compromise extracted from an alert.
type IOCType string

const (
	IOCTypeURL      IOCType = "url"
	IOCTypeDomain   IOCType = "domain"    // bare hostname, e.g. from DNS logs
	IOCTypeIP       IOCType = "ip"
	IOCTypeFileHash IOCType = "file_hash" // md5 | sha1 | sha256
)

// Hash algorithms supported for file_hash IOCs.
const (
	HashAlgoMD5    = "md5"
	HashAlgoSHA1   = "sha1"
	HashAlgoSHA256 = "sha256"
)

// IOC is a single indicator of compromise.
type IOC struct {
	Type  IOCType `json:"type"`
	Value string  `json:"value"`
	Algo  string  `json:"algo,omitempty"` // md5|sha1|sha256, only for file_hash
}

// Key returns the cache/dedup key for the IOC.
func (i IOC) Key() string {
	return string(i.Type) + ":" + i.Value
}

// EnrichmentVerdict is the aggregated verdict for a single IOC.
type EnrichmentVerdict string

const (
	VerdictMalicious  EnrichmentVerdict = "malicious"
	VerdictSuspicious EnrichmentVerdict = "suspicious"
	VerdictClean      EnrichmentVerdict = "clean"
	VerdictUnknown    EnrichmentVerdict = "unknown" // no data / lookup failed
)

// EnrichmentResult is the outcome of analyzing one IOC.
type EnrichmentResult struct {
	IOC     IOC               `json:"ioc"`
	Verdict EnrichmentVerdict `json:"verdict"`
	Stats   *AnalysisStats    `json:"stats,omitempty"` // VirusTotal (urls, hashes)
	Abuse   *AbuseReport      `json:"abuse,omitempty"` // AbuseIPDB (ips, domains)
	Cached  bool              `json:"cached"`
	Error   string            `json:"error,omitempty"`
}

// EnrichmentSummary aggregates the outcome of enriching one alert.
type EnrichmentSummary struct {
	IOCsFound   int `json:"iocs_found"`   // IOCs extracted (post-cap)
	LookedUp    int `json:"looked_up"`    // IOCs processed (cache hit or lookup)
	Malicious   int `json:"malicious"`    // verdict == malicious
	Suspicious  int `json:"suspicious"`   // verdict == suspicious
	Failures    int `json:"failures"`     // lookups that returned an error
}

// EnrichmentResponse is the payload returned to the Wazuh integration script.
type EnrichmentResponse struct {
	Enrichments []EnrichmentResult `json:"enrichments"`
	Summary     EnrichmentSummary  `json:"summary"`
}
