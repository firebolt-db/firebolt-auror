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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
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
	awsRegion := flag.String("aws-region", "us-east-1", "AWS region for ECR access")
	mode := flag.String("mode", "deny", "Auror admission controller operation mode: 'deny' or 'audit'")
	registry := flag.String("registry", "123456789123.dkr.ecr.us-east-1.amazonaws.com", "Comma-separated list of allowed registries")
	logLevel := flag.String("log-level", "info", "log level: info or debug")

	digestCacheSize := flag.Int("digest-cache-size", 1000, "Size of the image digest cache")
	digestCacheTTL := flag.Int("digest-cache-ttl", 12, "Time-to-live for the image digest cache in hours")
	tagCacheSize := flag.Int("tag-cache-size", 1000, "Size of the image tag cache")
	tagCacheTTL := flag.Int("tag-cache-ttl", 12, "Time-to-live for the image tag cache in hours")
	ownerCacheSize := flag.Int("owner-cache-size", 1000, "Size of the owner reference cache")
	ownerCacheTTL := flag.Int("owner-cache-ttl", 12, "Time-to-live for the owner reference cache in hours")
	useTagCache := flag.Bool("use-tag-cache", true, "Enable caching by image tags in addition to digests")

	flag.Parse()
	if *mode != "deny" && *mode != "audit" {
		logger.Error("Invalid mode", "mode", *mode)
	}
	registries := strings.Split(*registry, ",")
	// Trim spaces from each registry
	for i := range registries {
		registries[i] = strings.TrimSpace(registries[i])
	}
	switch *logLevel {
	case "debug":
		appLogLevel.Set(slog.LevelDebug)
	default:
		appLogLevel.Set(slog.LevelInfo)
	}
	logger.Info("Starting up", "log-level", *logLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("Starting auror admission controller", "mode", *mode)

	// Load AWS configuration
	logger.Info("Loading AWS configuration for region", "region", *awsRegion)

	awsRoleArn := os.Getenv("AWS_ROLE_ARN")
	var cfg aws.Config
	if awsRoleArn != "" {
		logger.Info("Assuming role", "arn", awsRoleArn)
		cf, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(*awsRegion),
			config.WithAssumeRoleCredentialOptions(func(options *stscreds.AssumeRoleOptions) {
				options.RoleARN = awsRoleArn
			}),
		)
		if err != nil {
			logger.Error("Unable to load AWS configuration with AssumeRole", "error", err)
			os.Exit(1)
		}
		cfg = cf
		// Verify AWS credentials
		creds, err := cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			logger.Error("Failed to retrieve AWS credentials", "error", err)
			os.Exit(1)
		}
		logger.Info("Successfully loaded AWS credentials with AssumeRole",
			"accessKeyID", creds.AccessKeyID,
			"expires", creds.Expires,
			"canExpire", creds.CanExpire)
	} else {
		cf, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(*awsRegion))
		if err != nil {
			logger.Error("Unable to load AWS configuration", "error", err)
			os.Exit(1)
		}
		cfg = cf
		logger.Info("Successfully loaded AWS configuration", "region", *awsRegion)
	}
	logger.Info("AWS configuration loaded successfully")

	// Create ECR client
	ecrClient := ecr.NewFromConfig(cfg)

	verifierConfig := cosign.VerifierConfig{
		PublicKeyPath: *publicKeyPath,
		HashAlgorithm: crypto.SHA256,
		Region:        *awsRegion,
		EcrClient:     ecrClient,
		Logger:        logger,
	}
	verifier, err := cosign.NewVerifier(verifierConfig)
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
