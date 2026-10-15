// Package domain contains the enterprise domain models shared across layers.
// It must stay free of any external dependencies.
package domain

// InputKind describes what kind of user input was detected.
type InputKind string

const (
	InputKindLink InputKind = "link"
	InputKindFile InputKind = "file"
)

// AnalysisStats holds the VirusTotal "last_analysis_stats" counters.
// Counters that are not mapped to a named field are preserved in Other.
type AnalysisStats struct {
	Harmless   int            `json:"harmless"`
	Malicious  int            `json:"malicious"`
	Suspicious int            `json:"suspicious"`
	Undetected int            `json:"undetected"`
	Timeout    int            `json:"timeout"`
	Other      map[string]int `json:"other,omitempty"`
}

// NewAnalysisStats builds AnalysisStats from raw VirusTotal counters.
// The "timeout" and "confirmed-timeout" counters are summed into Timeout.
func NewAnalysisStats(raw map[string]int) AnalysisStats {
	s := AnalysisStats{}
	for key, value := range raw {
		switch key {
		case "harmless":
			s.Harmless = value
		case "malicious":
			s.Malicious = value
		case "suspicious":
			s.Suspicious = value
		case "undetected":
			s.Undetected = value
		case "timeout", "confirmed-timeout":
			s.Timeout += value
		default:
			if s.Other == nil {
				s.Other = make(map[string]int)
			}
			s.Other[key] = value
		}
	}
	return s
}

// TotalEngines returns the total number of engines that reported a verdict.
func (s AnalysisStats) TotalEngines() int {
	total := s.Harmless + s.Malicious + s.Suspicious + s.Undetected + s.Timeout
	for _, v := range s.Other {
		total += v
	}
	return total
}

// AbuseReport holds the AbuseIPDB "check" report for a single IP address.
type AbuseReport struct {
	IPAddress            string   `json:"ipAddress"`
	IsPublic             bool     `json:"isPublic"`
	IPVersion            int      `json:"ipVersion"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	UsageType            string   `json:"usageType"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
}

// AnalysisResult is the outcome of analyzing a single user input.
type AnalysisResult struct {
	Input      string        `json:"input"`
	Kind       InputKind     `json:"kind"`
	ResolvedIP string        `json:"resolvedIp,omitempty"` // set only for links
	Stats      AnalysisStats `json:"stats"`
	Abuse      *AbuseReport  `json:"abuse,omitempty"` // set only for links with a resolvable host
}
