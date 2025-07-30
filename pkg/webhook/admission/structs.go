package admission

import (
	"log/slog"
	"time"

	"github.com/firebolt-db/firebolt-auror/pkg/webhook/cache"
	"github.com/firebolt-db/firebolt-auror/pkg/webhook/cosign"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CacheConfig struct {
	DigestSize int
	DigestTTL  time.Duration
	TagSize    int
	TagTTL     time.Duration
	OwnerSize  int
	OwnerTTL   time.Duration
}

type Validator struct {
	verifier    *cosign.Verifier
	ownerCache  cache.CacheInterface
	cache       cache.CacheInterface
	tagCache    cache.CacheInterface
	useTagCache bool
	mode        string
	registries  []string
	logger      *slog.Logger
}

type VerificationResult struct {
	Image  string
	Digest string
	Valid  bool
	Error  error
}

type Resource struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		// For Pod
		Containers     []Container `json:"containers"`
		InitContainers []Container `json:"initContainers"`
		// For Deployment, StatefulSet, DaemonSet, ReplicaSet, Job
		Template struct {
			Spec struct {
				Containers     []Container `json:"containers"`
				InitContainers []Container `json:"initContainers"`
			} `json:"spec"`
		} `json:"template"`
		// For CronJob
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers     []Container `json:"containers"`
						InitContainers []Container `json:"initContainers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

type Container struct {
	Image string `json:"image"`
}
