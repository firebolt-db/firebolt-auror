package cosign

import (
	"crypto"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/sigstore/sigstore/pkg/signature"
)

// add expiration data of token
// add token itself also
// also the publickey,
type VerifierConfig struct {
	PublicKeyPath string
	PublicKey     signature.Verifier
	HashAlgorithm crypto.Hash
	Region        string
	EcrClient     *ecr.Client
	Logger        *slog.Logger
	ExpireTime    time.Time
	Token         string
}

type Verifier struct {
	config VerifierConfig
}
