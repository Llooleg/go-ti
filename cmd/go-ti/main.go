// Command go-ti is a simple threat intelligence tool: it checks links and
// files against VirusTotal and AbuseIPDB.
//
// By default it runs as a one-shot console tool; pass -web (or -addr) to
// start the browser GUI instead.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-ti/internal/config"
	"go-ti/internal/delivery/cli"
	"go-ti/internal/delivery/web"
	"go-ti/internal/repository/abuseipdb"
	"go-ti/internal/repository/dnsresolver"
	"go-ti/internal/repository/virustotal"
	"go-ti/internal/usecase"
	"go-ti/pkg/checksum"
	"go-ti/pkg/ratelimit"
)

// webShutdownTimeout bounds the graceful shutdown of the web server.
const webShutdownTimeout = 10 * time.Second

func main() {
	webMode := flag.Bool("web", false, "start the web GUI instead of the one-shot console mode")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address for the web GUI (implies -web)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *webMode || addrFlagSet(), *addr, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, webMode bool, addr string, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	vtRepo := virustotal.New(cfg.VirusTotalAPIKey)
	abuseRepo := abuseipdb.New(cfg.AbuseIPDBAPIKey)
	resolver := dnsresolver.New()

	service := usecase.NewAnalysisService(vtRepo, abuseRepo, resolver, checksum.Hasher{})

	if webMode {
		enricher, err := usecase.NewEnrichmentService(usecase.EnrichmentDeps{
			VirusTotal:        vtRepo,
			Abuse:             abuseRepo,
			Resolver:          resolver,
			Extractor:         usecase.NewIOCExtractor(cfg.Enrichment.MaxIOCsPerAlert, cfg.Enrichment.DomainSkipSuffixes),
			Cache:             usecase.NewVerdictCache(cfg.Enrichment.IOCCacheTTL),
			VirusTotalLimiter: ratelimit.New(cfg.Enrichment.VTRatePerMin),
			AbuseLimiter:      ratelimit.New(cfg.Enrichment.AbuseRatePerMin),
		})
		if err != nil {
			return fmt.Errorf("build enrichment service: %w", err)
		}
		return runWebServer(ctx, addr, service, enricher, cfg)
	}

	handler := cli.New(service, os.Stdin, os.Stdout)
	return handler.Run(ctx, args)
}

func runWebServer(ctx context.Context, addr string, service *usecase.AnalysisService, enricher *usecase.EnrichmentService, cfg config.Config) error {
	logger := slog.Default()

	handler := web.New(service, logger,
		web.WithEnrichment(enricher, cfg.Enrichment.WebToken, cfg.Enrichment.EnrichTimeout),
	).Handler()

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Analyses call several external APIs sequentially, so writes can be slow.
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("web interface listening", "addr", "http://"+addr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("web server: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down web interface")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), webShutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

// addrFlagSet reports whether the -addr flag was set explicitly on the
// command line, in which case web mode is implied.
func addrFlagSet() bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "addr" {
			set = true
		}
	})
	return set
}
