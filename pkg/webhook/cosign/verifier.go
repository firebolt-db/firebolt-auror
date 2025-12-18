package cosign

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func NewVerifier(ctx context.Context, config VerifierConfig) (*Verifier, error) {
	if config.HashAlgorithm == 0 {
		config.HashAlgorithm = crypto.SHA256
	}

	// parse the provider
	switch config.Provider {
	case ProviderAWS:
		// AWS_ECR_REGION is used for the ECR client
		// it should match with the region of the ECR registry
		// our case it is us-east-1
		region, ok := os.LookupEnv("AWS_ECR_REGION")
		if !ok {
			region = "us-east-1"
		}
		ecrClient, err := NewECRClient(ctx, config.Logger, region, config.InCluster, config.Registries)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECR client: %w", err)
		}
		config.RegistryClient = ecrClient
	case ProviderOpenRegistry:
		openRegistryClient, err := NewOpenRegistryClient(ctx, config.Logger, config.InCluster, config.Registries)
		if err != nil {
			return nil, fmt.Errorf("failed to create Open Registry client: %w", err)
		}
		config.RegistryClient = openRegistryClient
	}

	publicKey, err := loadPublicKey(config.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	config.PublicKey = publicKey
	return &Verifier{
		config: config,
	}, nil
}

func (v *Verifier) VerifySignature(image string) (bool, string, error) {

	ctx := context.Background()
	v.config.Logger.Debug("Starting signature verification for image", "image", image)

	// Parse the image reference
	imageRef, err := name.ParseReference(image)
	if err != nil {
		return false, "", fmt.Errorf("parsing reference: %w", err)
	}
	v.config.Logger.Debug("Parsed reference", "image", imageRef.String())

	// remote options
	opts := []remote.Option{}
	switch v.config.Provider {
	case "aws":
		awsOpts, err := v.config.RegistryClient.GetRemoteOption(ctx)
		if err != nil {
			return false, "", fmt.Errorf("failed to get ECR remote option: %w", err)
		}
		opts = append(opts, awsOpts)
	case ProviderOpenRegistry:
		openRegistryOpts, err := v.config.RegistryClient.GetRemoteOption(ctx)
		if err != nil {
			return false, "", fmt.Errorf("failed to get Open Registry remote option: %w", err)
		}
		opts = append(opts, openRegistryOpts)
	default:
		return false, "", fmt.Errorf("invalid provider: %s", v.config.Provider)
	}

	checkOpts := &cosign.CheckOpts{
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		IgnoreTlog:         true,
		Offline:            true,
		SigVerifier:        v.config.PublicKey,
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
	}

	// Cosign takes over the rest...
	v.config.Logger.Debug("Starting Cosign signature verification...")

	// resolve ref to a digest
	digest, err := ociremote.ResolveDigest(imageRef, checkOpts.RegistryClientOpts...)
	if err != nil {
		v.config.Logger.Error("Cannot get remote digest", "error", err, "image", imageRef.String())
		return false, "", fmt.Errorf("cannot get remote digest: %w", err)
	}

	// pass digest directly to avoid a second remote lookup
	sigs, err := validSignatures(ctx, digest, checkOpts)
	if err != nil {
		v.config.Logger.Error("Failed to verify signature", "error", err, "image", imageRef.String(), "digest", digest.Identifier())
		return false, "", fmt.Errorf("failed to verify signature: %w", err)
	}

	if len(sigs) > 0 {
		v.config.Logger.Debug("Signature verification successful for image", "image", imageRef.String(), "digest", digest.Identifier())
		v.config.Logger.Debug("Found valid signature(s)", "count", len(sigs))
		payload, err := sigs[0].Payload()
		if err != nil {
			v.config.Logger.Error("Failed to get first signature payload", "error", err, "image", imageRef.String(), "digest", digest.Identifier())
			return false, "", fmt.Errorf("failed to get first signature payload: %w", err)
		}
		var payloadJSON map[string]interface{}
		if err := json.Unmarshal(payload, &payloadJSON); err != nil {
			v.config.Logger.Error("Failed to parse first signature payload", "error", err, "image", imageRef.String(), "digest", digest.Identifier())
			return false, "", fmt.Errorf("failed to parse first signature payload: %w", err)
		}

		dockerManifestDigest := payloadJSON["critical"].(map[string]interface{})["image"].(map[string]interface{})["docker-manifest-digest"].(string)
		v.config.Logger.Debug("Manifest digest from first signature", "docker-manifest-digest", dockerManifestDigest, "image", imageRef.String(), "digest", digest.Identifier())
		return true, dockerManifestDigest, nil
	}

	v.config.Logger.Info("No valid signatures found for image", "image", imageRef.String(), "digest", digest.Identifier())
	return false, "", nil
}

func validSignatures(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	sigs, _, err := cosign.VerifyImageSignatures(ctx, ref, checkOpts)
	return sigs, err
}

func loadPublicKey(path string) (signature.Verifier, error) {
	pubKey, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	pk, err := cryptoutils.UnmarshalPEMToPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	verifier, err := signature.LoadVerifier(pk, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier from public key: %v", err)
	}

	return verifier, nil
}
