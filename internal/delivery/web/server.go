// Package web is the HTTP delivery layer of the application:
// it serves the browser GUI and the JSON API around the analysis service.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"go-ti/internal/domain"
)

// maxRequestBody limits the size of a request body accepted by the API.
const maxRequestBody = 1 << 20 // 1 MiB

// staticFS holds the GUI assets embedded into the binary.
//
//go:embed all:static
var staticFS embed.FS

// AnalysisService is the business capability exposed to this transport layer.
type AnalysisService interface {
	Analyze(ctx context.Context, input string) (domain.AnalysisResult, error)
}

// Server serves the web GUI and the JSON API.
type Server struct {
	service AnalysisService
	logger  *slog.Logger
	mux     *http.ServeMux
}

// New creates a web server around the given analysis service.
// A nil logger falls back to slog.Default().
func New(service AnalysisService, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		service: service,
		logger:  logger,
		mux:     http.NewServeMux(),
	}

	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.Handle("GET /static/", http.FileServerFS(staticFS))
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/analyze", s.handleAnalyze)

	return s
}

// Handler returns the fully middleware-wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.withLogging(s.withSecurityHeaders(s.withRecovery(s.mux)))
}

type analyzeRequest struct {
	Input string `json:"input"`
}

type analyzeResponse struct {
	Result  *domain.AnalysisResult `json:"result,omitempty"`
	Warning string                 `json:"warning,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req analyzeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Input) == "" {
		s.writeError(w, http.StatusBadRequest, "input must not be empty")
		return
	}

	result, err := s.service.Analyze(r.Context(), strings.TrimSpace(req.Input))
	switch {
	case err == nil:
		s.writeJSON(w, http.StatusOK, analyzeResponse{Result: &result})
	case result.Input != "":
		// Partial result: the client shows what was collected plus a warning.
		s.writeJSON(w, http.StatusOK, analyzeResponse{Result: &result, Warning: err.Error()})
	default:
		s.writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "index page not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		s.logger.Error("write index page", "error", err)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("encode response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, analyzeResponse{Error: msg})
}
