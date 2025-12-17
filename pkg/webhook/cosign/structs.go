package cosign

import (
	"crypto"
	"log/slog"

	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	ProviderAWS          = "aws"
	ProviderOpenRegistry = "open-registry"
)

// add expiration data of token
// add token itself also
// also the publickey,
type VerifierConfig struct {
	PublicKeyPath  string
	PublicKey      signature.Verifier
	HashAlgorithm  crypto.Hash
	Provider       string
	InCluster      bool
	Registries     []string
	RegistryClient RegistryClient
	Logger         *slog.Logger
}

type Verifier struct {
	config VerifierConfig
}
