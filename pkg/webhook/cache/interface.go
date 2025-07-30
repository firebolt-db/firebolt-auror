package cache

import (
	"context"
	"log/slog"
	"time"
)

type CacheInterface interface {
	Add(ctx context.Context, key string, entry CacheEntry)
	Get(ctx context.Context, key string) (CacheEntry, bool)
	Len() int
	Remove(ctx context.Context, key string)
}

func CacheFactory(maxSize int, ttl time.Duration, cacheType string, logger *slog.Logger) CacheInterface {
	return NewRistrettoCache(maxSize, ttl, cacheType, logger)
}
