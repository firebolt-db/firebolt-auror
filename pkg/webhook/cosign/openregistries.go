package cosign

import (
	"context"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// NewOpenRegistryClient creates a new Open Registry client.
// examples: ttl.sh, docker.io, ghcr.io, etc.
func NewOpenRegistryClient(ctx context.Context, logger *slog.Logger, inCluster bool, registries []string) (*OpenRegistryClient, error) {
	return &OpenRegistryClient{}, nil
}

type OpenRegistryClient struct {
	InCluster  bool
	Registries []string
	Logger     *slog.Logger
}

// GetRemoteOption returns the remote option for the Open Registry. It means registry without authentication.
func (o *OpenRegistryClient) GetRemoteOption(ctx context.Context) (remote.Option, error) {
	return remote.WithAuth(nil), nil
}
