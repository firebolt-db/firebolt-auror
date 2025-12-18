package main

import (
	"context"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/firebolt-db/firebolt-auror/pkg/otelutils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/firebolt-db/firebolt-auror/pkg/webhook/admission"
	"github.com/firebolt-db/firebolt-auror/pkg/webhook/cosign"
	"github.com/firebolt-db/firebolt-auror/pkg/webhook/metrics"
)

const (
	ModeAudit     = "audit"
	ModeDeny      = "deny"
	LogLevelInfo  = "info"
	LogLevelDebug = "debug"
)

func main() {
	// logger
	var appLogLevel = new(slog.LevelVar)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: appLogLevel}))
	slog.SetDefault(logger)
	port := flag.Int("port", 8443, "Port to listen on")
	admPort := flag.Int("adm-port", 8080, "Port to listen on for administrative requests")
	certFile := flag.String("cert", "/certs/tls.crt", "File containing the x509 Certificate for HTTPS")
	keyFile := flag.String("key", "/certs/tls.key", "File containing the x509 private key for HTTPS")
	publicKeyPath := flag.String("public-key", "/cosign/cosign.pub", "Path to the public key file")
	provider := flag.String("provider", cosign.ProviderOpenRegistry, "Provider for the registry: 'aws' or 'open-registry'. Lower case is required.")
	inCluster := flag.Bool("in-cluster", false, "Whether the Auror is in-cluster")
	mode := flag.String("mode", ModeDeny, "Auror admission controller operation mode: 'deny' or 'audit'")
	registry := flag.String("registry", "ttl.sh/", "Comma-separated list of allowed registries")
	logLevel := flag.String("log-level", LogLevelInfo, "log level: info or debug")

	digestCacheSize := flag.Int("digest-cache-size", 1000, "Size of the image digest cache")
	digestCacheTTL := flag.Int("digest-cache-ttl", 12, "Time-to-live for the image digest cache in hours")
	tagCacheSize := flag.Int("tag-cache-size", 1000, "Size of the image tag cache")
	tagCacheTTL := flag.Int("tag-cache-ttl", 12, "Time-to-live for the image tag cache in hours")
	ownerCacheSize := flag.Int("owner-cache-size", 1000, "Size of the owner reference cache")
	ownerCacheTTL := flag.Int("owner-cache-ttl", 12, "Time-to-live for the owner reference cache in hours")
	useTagCache := flag.Bool("use-tag-cache", true, "Enable caching by image tags in addition to digests")

	flag.Parse()
	registries := strings.Split(*registry, ",")
	// Trim spaces from each registry
	for i := range registries {
		registries[i] = strings.TrimSpace(registries[i])
	}
	switch *logLevel {
	case LogLevelDebug:
		appLogLevel.Set(slog.LevelDebug)
	default:
		appLogLevel.Set(slog.LevelInfo)
	}
	logger.Info("Starting up", "log-level", *logLevel)
	if *mode != ModeDeny && *mode != ModeAudit {
		logger.Error("Invalid mode", "mode", *mode)
	}
	if *provider != cosign.ProviderAWS && *provider != cosign.ProviderOpenRegistry {
		logger.Error("Invalid provider", "provider", *provider)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("Starting auror admission controller", "mode", *mode)

	verifierConfig := cosign.VerifierConfig{
		PublicKeyPath: *publicKeyPath,
		HashAlgorithm: crypto.SHA256,
		Provider:      *provider,
		InCluster:     *inCluster,
		Registries:    registries,
		Logger:        logger,
	}
	verifier, err := cosign.NewVerifier(ctx, verifierConfig)
	if err != nil {
		logger.Error("Failed to create verifier", "error", err)
		os.Exit(1)
	}

	validator := admission.NewValidator(verifier, *mode, registries,
		admission.CacheConfig{
			DigestSize: *digestCacheSize,
			DigestTTL:  time.Duration(*digestCacheTTL) * time.Hour,
			TagSize:    *tagCacheSize,
			TagTTL:     time.Duration(*tagCacheTTL) * time.Hour,
			OwnerSize:  *ownerCacheSize,
			OwnerTTL:   time.Duration(*ownerCacheTTL) * time.Hour,
		},
		*useTagCache, logger)

	// setupOTelSDK: enableTraces, enableLogs bool values
	otelShutdown, err := otelutils.SetupOTelSDK(ctx)
	if err != nil {
		logger.Error("Error setting up OpenTelemetry SDK", "error", err.Error())
		os.Exit(1)
	}

	defer func() {
		err = errors.Join(err, otelShutdown(ctx))
	}()

	if err := metrics.InitMetrics(ctx); err != nil {
		logger.Error("Error initializing cache metrics", "error", err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", validator.ValidateAdmission)

	logger.Info("Starting auror admission controller server", "port", *port)
	logger.Info("Using public key", "path", *publicKeyPath)

	handler := otelhttp.NewHandler(mux, "/")
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%v", *port),
		Handler: handler,
	}

	admMux := http.NewServeMux()
	admMux.Handle("/metrics", promhttp.Handler())
	admMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("OK\n"))
		if err != nil {
			logger.Error("Error writing response", "error", err)
		}
	})
	admServer := &http.Server{
		Addr:    fmt.Sprintf(":%v", *admPort),
		Handler: admMux,
	}
	go func() {
		if err := admServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start administrative server", "error", err)
		}
	}()

	go func() {
		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}
	if err := admServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Administrative server forced to shutdown", "error", err)
	}

	logger.Info("Server shutdown complete")
}
