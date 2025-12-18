package cosign

import (
	"context"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type RegistryClient interface {
	GetRemoteOption(ctx context.Context) (remote.Option, error)
}
