package inputparse

import "testing"

func TestIsLink(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"https url", "https://example.com/path?q=1", true},
		{"http url", "http://example.com", true},
		{"url with spaces", "  https://example.com  ", true},
		{"ip host", "http://127.0.0.1:8080/x", true},
		{"ftp scheme", "ftp://example.com", false},
		{"bare domain", "example.com", false},
		{"windows path", `C:\Users\me\file.txt`, false},
		{"unix path", "/etc/passwd", false},
		{"relative path", "./file.txt", false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLink(tc.in); got != tc.want {
				t.Errorf("IsLink(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
