package usecase_test

import (
	"reflect"
	"strings"
	"testing"

	"go-ti/internal/domain"
	"go-ti/internal/usecase"
)

const (
	sha256Hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	sha1Hex   = "a9993e364706816aba3e25717850c26c9cd0d89d"
	md5Hex    = "900150983cd24fb0d6963f7d28e17f72"
)

func extract(t *testing.T, alert map[string]any, maxIOCs int, suffixes []string) []domain.IOC {
	t.Helper()
	return usecase.NewIOCExtractor(maxIOCs, suffixes).Extract(alert)
}

func TestExtractSyscheckHashes(t *testing.T) {
	alert := map[string]any{
		"agent": map[string]any{"id": "001"},
		"data": map[string]any{
			"syscheck": map[string]any{
				"path":         "/tmp/warez.exe",
				"sha256_after": strings.ToUpper(sha256Hex),
			},
		},
	}

	iocs := extract(t, alert, 10, nil)
	want := []domain.IOC{{Type: domain.IOCTypeFileHash, Value: sha256Hex, Algo: domain.HashAlgoSHA256}}
	if !reflect.DeepEqual(iocs, want) {
		t.Errorf("got %+v, want %+v", iocs, want)
	}
}

func TestExtractSysmonHashes(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"win": map[string]any{
				"eventdata": map[string]any{
					"hashes": "SHA256=" + sha256Hex + ",MD5=" + md5Hex + ",IMPHASH=" + sha1Hex,
				},
			},
		},
	}

	iocs := extract(t, alert, 10, nil)
	if len(iocs) != 2 {
		t.Fatalf("got %d IOCs, want 2: %+v", len(iocs), iocs)
	}
	if iocs[0].Algo != domain.HashAlgoSHA256 || iocs[0].Value != sha256Hex {
		t.Errorf("first IOC = %+v", iocs[0])
	}
	if iocs[1].Algo != domain.HashAlgoMD5 || iocs[1].Value != md5Hex {
		t.Errorf("second IOC = %+v", iocs[1])
	}
}

func TestExtractSuricataURL(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"id":   "abc",
			"url":  "http://evil.example/payload?a=1",
			"dest": map[string]any{"ip": "203.0.113.9"},
		},
	}

	iocs := extract(t, alert, 10, nil)
	want := []domain.IOC{{Type: domain.IOCTypeURL, Value: "http://evil.example/payload?a=1"}}
	if !reflect.DeepEqual(iocs, want) {
		t.Errorf("got %+v, want %+v", iocs, want)
	}
}

func TestExtractDNSDomains(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"dns": map[string]any{
				"queries": []any{
					map[string]any{"name": "malicious-cdn.EXAMPLE."},
					map[string]any{"name": "ok.example"},
					"garbage-string",
				},
				"rrname": "another.evil.example",
			},
		},
	}

	iocs := extract(t, alert, 10, nil)
	want := []domain.IOC{
		{Type: domain.IOCTypeDomain, Value: "malicious-cdn.example"},
		{Type: domain.IOCTypeDomain, Value: "ok.example"},
		{Type: domain.IOCTypeDomain, Value: "another.evil.example"},
	}
	if !reflect.DeepEqual(iocs, want) {
		t.Errorf("got %+v, want %+v", iocs, want)
	}
}

func TestExtractSysmonDNSQuery(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"win": map[string]any{
				"eventdata": map[string]any{
					"queryName": "Updates.MalwareCdn.example",
				},
			},
		},
	}

	iocs := extract(t, alert, 10, nil)
	want := []domain.IOC{{Type: domain.IOCTypeDomain, Value: "updates.malwarecdn.example"}}
	if !reflect.DeepEqual(iocs, want) {
		t.Errorf("got %+v, want %+v", iocs, want)
	}
}

func TestExtractIPsSkipsPrivate(t *testing.T) {
	alert := map[string]any{
		"srcip": "8.8.8.8",
		"data": map[string]any{
			"srcip": "192.168.1.10",
			"dstip": "203.0.113.9",
		},
	}

	iocs := extract(t, alert, 10, nil)
	want := []domain.IOC{
		{Type: domain.IOCTypeIP, Value: "203.0.113.9"},
		{Type: domain.IOCTypeIP, Value: "8.8.8.8"},
	}
	if !reflect.DeepEqual(iocs, want) {
		t.Errorf("got %+v, want %+v", iocs, want)
	}
}

func TestExtractDomainSuffixSkipping(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"dns": map[string]any{"rrname": "wpad.local"},
		},
	}

	if iocs := extract(t, alert, 10, nil); len(iocs) != 0 {
		t.Errorf("default suffixes should skip .local, got %+v", iocs)
	}

	if iocs := extract(t, alert, 10, []string{"internal"}); len(iocs) != 1 {
		t.Errorf("custom suffixes should keep .local, got %+v", iocs)
	}
}

func TestExtractInvalidValues(t *testing.T) {
	alert := map[string]any{
		"data": map[string]any{
			"syscheck": map[string]any{"sha256_after": "not-a-hash"},
			"url":      "notaurl",
			"dns":      map[string]any{"rrname": "-invalid-.tld"},
		},
	}

	if iocs := extract(t, alert, 10, nil); len(iocs) != 0 {
		t.Errorf("invalid values should be dropped, got %+v", iocs)
	}
}

func TestExtractDeduplicatesAndCaps(t *testing.T) {
	alert := map[string]any{
		"srcip": "8.8.8.8",
		"data": map[string]any{
			"srcip": "8.8.8.8",
			"syscheck": map[string]any{
				"sha256_after": sha256Hex,
				"md5_after":    md5Hex,
			},
		},
	}

	iocs := extract(t, alert, 2, nil)
	if len(iocs) != 2 {
		t.Fatalf("cap not enforced, got %d IOCs: %+v", len(iocs), iocs)
	}
	if iocs[0].Value != sha256Hex || iocs[1].Value != md5Hex {
		t.Errorf("expected hashes first (deterministic order), got %+v", iocs)
	}
}

func TestExtractUnknownLayoutYieldsNothing(t *testing.T) {
	if iocs := extract(t, map[string]any{"unexpected": 42}, 10, nil); len(iocs) != 0 {
		t.Errorf("unknown layout should yield no IOCs, got %+v", iocs)
	}
	if iocs := extract(t, nil, 10, nil); len(iocs) != 0 {
		t.Errorf("nil alert should yield no IOCs, got %+v", iocs)
	}
}
