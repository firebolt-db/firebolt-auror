package cache

import (
	"log/slog"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
)

type CacheEntry struct {
	Valid     bool
	Timestamp time.Time
}
type ristrettoMetricsCollector struct {
	cache     *ristretto.Cache[string, CacheEntry]
	cacheType string
}

type ristrettoCache struct {
	cache     *ristretto.Cache[string, CacheEntry]
	cacheType string
	ttl       time.Duration
	collector *ristrettoMetricsCollector
	logger    *slog.Logger
}
