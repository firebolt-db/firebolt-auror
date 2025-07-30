package cosign

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if config.HashAlgorithm == 0 {
		config.HashAlgorithm = crypto.SHA256
	}

	token, expiresAt, err := getECRAuthToken(context.Background(), config.EcrClient)
	if err != nil {
		return nil, err
	}
	config.Token = token
	config.ExpireTime = expiresAt
	config.PublicKey, err = loadPublicKey(config.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		config: config,
	}, nil
}

func (v *Verifier) VerifySignature(image string) (bool, string, error) {

	ctx := context.Background()
	v.config.Logger.Debug("Starting signature verification for image", "image", image)

	// Parse the image reference
	ref, err := name.ParseReference(image)
	if err != nil {
		return false, "", fmt.Errorf("parsing reference: %w", err)
	}
	v.config.Logger.Debug("Parsed reference", "reference", ref.String())

	if v.config.ExpireTime.Before(time.Now()) {
		v.config.Logger.Error("ECR token expired, renewing...", "expiredTime", v.config.ExpireTime)
		v.config.Token, v.config.ExpireTime, err = getECRAuthToken(ctx, v.config.EcrClient)
		if err != nil {
			v.config.Logger.Error("Failed to renew ECR auth token", "error", err)
			// Pod creation is allowed only until the token is renewed
			return true, "", fmt.Errorf("failed to renew ECR auth token: %w, allowing pod creation", err)
		}
	}

	opts := []remote.Option{
		remote.WithAuth(&authn.Basic{
			Username: "AWS",
			Password: v.config.Token,
		}),
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
	sigs, err := validSignatures(ctx, ref, checkOpts)
	if err != nil {
		v.config.Logger.Error("Failed to verify signature", "error", err)
		return false, "", fmt.Errorf("failed to verify signature: %w", err)
	}

	if len(sigs) > 0 {
		v.config.Logger.Debug("Signature verification successful for image", "image", ref.String())
		v.config.Logger.Debug("Found valid signature(s)", "count", len(sigs))
		payload, err := sigs[0].Payload()
		if err != nil {
			v.config.Logger.Error("Failed to get signature payload", "error", err)
			return false, "", fmt.Errorf("failed to get signature payload: %w", err)
		}
		var payloadJSON map[string]interface{}
		if err := json.Unmarshal(payload, &payloadJSON); err != nil {
			v.config.Logger.Error("Failed to parse payload", "error", err)
			return false, "", fmt.Errorf("failed to parse payload: %w", err)
		}

		digest := payloadJSON["critical"].(map[string]interface{})["image"].(map[string]interface{})["docker-manifest-digest"].(string)
		v.config.Logger.Debug("Manifest digest from signature", "digest", digest)
		return true, digest, nil
	}

	v.config.Logger.Info("No valid signatures found for image", "image", ref.String())
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

func getECRAuthToken(ctx context.Context, ecrClient *ecr.Client) (string, time.Time, error) {
	// Get ECR authorization token
	result, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
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
