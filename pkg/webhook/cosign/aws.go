package cosign

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrhelper "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	ecrapi "github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ECRClient is a client for the ECR API
type ECRClient struct {
	ProviderAuth string
	Client       *ecr.Client
	ExpireTime   time.Time
	Token        string
	InCluster    bool
	Helper       *ecrhelper.ECRHelper
	Registries   []string
	Logger       *slog.Logger
}

func NewECRClient(ctx context.Context, logger *slog.Logger, region string, inCluster bool, registries []string) (*ECRClient, error) {
	logger.Info("Loading AWS configuration for region", "region", region)

	awsRoleArn := os.Getenv("AWS_ROLE_ARN")
	var cfg aws.Config
	if awsRoleArn != "" {
		logger.Info("Assuming role", "arn", awsRoleArn)
		cf, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
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
		cf, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			logger.Error("Unable to load AWS configuration", "error", err)
			os.Exit(1)
		}
		cfg = cf
		logger.Info("Successfully loaded AWS configuration", "region", region)
	}
	logger.Info("AWS configuration loaded successfully")

	// Create ECR client
	ecrConfig := ecr.NewFromConfig(cfg)
	ecrClient := ECRClient{Client: ecrConfig, Logger: logger, ProviderAuth: "AWS", InCluster: inCluster, Registries: registries}
	logger.Info("Creating ECR authorization token")
	token, expireTime, err := ecrClient.getAuthorizationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ECR authorization token: %w", err)
	}
	ecrClient.Token = token
	ecrClient.ExpireTime = expireTime
	if inCluster {
		logger.Info("Creating ECR helper")
		apiClient := ecrapi.DefaultClientFactory{}
		apiClient.NewClient(cfg)
		helperFactory := ecrhelper.WithClientFactory(apiClient)
		helper := ecrhelper.NewECRHelper(helperFactory)
		ecrClient.Helper = helper
		// return &ecrClient, nil
	}
	return &ecrClient, nil
}

func (e *ECRClient) GetRemoteOption(ctx context.Context) (remote.Option, error) {

	if e.ExpireTime.Before(time.Now()) {
		e.Logger.Error("ECR token expired, renewing...", "expiredTime", e.ExpireTime)
		token, expireTime, err := e.getAuthorizationToken(ctx)
		if err != nil {
			e.Logger.Error("Failed to renew ECR auth token", "error", err)
			// Pod creation is allowed only until the token is renewed
			return nil, fmt.Errorf("failed to renew ECR auth token: %w, allowing pod creation", err)
		}
		e.Token = token
		e.ExpireTime = expireTime
	}

	if !e.InCluster {
		e.Logger.Debug("Getting only ECR authorization token from basic authentication")
		basicAuth := authn.Basic{
			Username: e.ProviderAuth,
			Password: e.Token,
		}
		return remote.WithAuth(&basicAuth), nil
	}

	ecrKC := authn.NewKeychainFromHelper(e.Helper)
	sliceKeychains := make([]authn.Keychain, len(e.Registries))
	for i, registry := range e.Registries {
		sliceKeychains[i] = KeychainFromAuthenticator(authn.FromConfig(authn.AuthConfig{
			Username: e.ProviderAuth,
			Password: e.Token,
		}), registry)
	}
	// append the ecrKC to the sliceKeychains
	sliceKeychains = append(sliceKeychains, ecrKC)
	e.Logger.Debug("Returning multi keychain", "count", len(sliceKeychains))
	multi := authn.NewMultiKeychain(sliceKeychains...)
	opt := remote.WithAuthFromKeychain(multi)

	return opt, nil
}

func (e *ECRClient) getAuthorizationToken(ctx context.Context) (string, time.Time, error) {
	// Get ECR authorization token
	result, err := e.Client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get ECR authorization token: %w", err)
	}

	if len(result.AuthorizationData) == 0 {
		return "", time.Time{}, fmt.Errorf("no authorization data returned from ECR")
	}
	// Decode the base64 token
	token := *result.AuthorizationData[0].AuthorizationToken
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode ECR token: %w", err)
	}

	// The decoded token is in the format "AWS:password"
	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return "", time.Time{}, fmt.Errorf("invalid token format")
	}

	return parts[1], *result.AuthorizationData[0].ExpiresAt, nil
}

// staticKeychain wraps a single Authenticator as a Keychain.
// Optionally restrict it to a specific registry host.
type staticKeychain struct {
	auth         authn.Authenticator
	onlyRegistry string // e.g. "123456789012.dkr.ecr.us-east-1.amazonaws.com"; empty = all
}

func (k staticKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	if k.onlyRegistry == "" || res.RegistryStr() == k.onlyRegistry {
		return k.auth, nil
	}
	// Returning Anonymous signals "no creds here; try the next keychain".
	return authn.Anonymous, nil
}

// Helper to build a static keychain from any authenticator.
func KeychainFromAuthenticator(a authn.Authenticator, onlyRegistry string) authn.Keychain {
	return staticKeychain{auth: a, onlyRegistry: onlyRegistry}
}
