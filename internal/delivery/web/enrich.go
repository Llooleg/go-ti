package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

const bearerPrefix = "Bearer "

// withAuth enforces the bearer token (when configured) on all /api/ routes.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, bearerPrefix) ||
				subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, bearerPrefix)), []byte(s.token)) != 1 {
				s.writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleEnrich enriches a Wazuh alert with threat-intelligence verdicts.
// The response is always 200 when the payload parses; per-IOC failures are
// part of the payload (see internal/domain EnrichmentResponse).
func (s *Server) handleEnrich(w http.ResponseWriter, r *http.Request) {
	if s.enricher == nil {
		s.writeError(w, http.StatusServiceUnavailable, "enrichment is not configured")
		return
	}

	var alert map[string]any
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err := decoder.Decode(&alert); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if alert == nil {
		s.writeError(w, http.StatusBadRequest, "request body must be a JSON object")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.enrichTimeout)
	defer cancel()

	response := s.enricher.Enrich(ctx, alert)
	s.writeJSON(w, http.StatusOK, response)
}
