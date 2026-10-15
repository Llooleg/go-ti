// Package inputparse provides helpers for classifying raw user input.
package inputparse

import (
	"net/url"
	"strings"
)

// IsLink reports whether s is an http or https URL with a non-empty host.
func IsLink(s string) bool {
	u, err := url.ParseRequestURI(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
