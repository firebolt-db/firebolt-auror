package cache

import (
	"context"
	"log/slog"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
	"github.com/firebolt-db/firebolt-auror/pkg/webhook/metrics"
)

// need to implement this for the cache interface
func (r *ristrettoCache) Add(ctx context.Context, key string, entry CacheEntry) {
	stored := r.cache.SetWithTTL(key, entry, 1, r.ttl)
	r.cache.Wait()

	if !stored {
		r.logger.Error("Failed to add to cache", "error", "cache_full")
	}
}

// need to implement this for the cache interface
func (r *ristrettoCache) Get(ctx context.Context, key string) (CacheEntry, bool) {
	value, found := r.cache.Get(key)
	if !found {
		return CacheEntry{}, false
	}
	return value, found
}

// need to implement this for the cache interface
func (r *ristrettoCache) Len() int {
	if r.cache.Metrics == nil {
		return 0
	}
	return int(r.cache.Metrics.KeysAdded() - r.cache.Metrics.KeysEvicted())
}

// need to implement this for the cache interface
func (r *ristrettoCache) Remove(ctx context.Context, key string) {
	r.cache.Del(key)
	r.cache.Wait()
}

func (r *ristrettoMetricsCollector) startCollection() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		r.collect(context.Background())
	}
}

func (r *ristrettoMetricsCollector) collect(ctx context.Context) {
	if r.cache == nil || r.cache.Metrics == nil {
		return
	}
	// Record all metrics at once during collection
	metrics.RecordCacheHit(ctx, r.cacheType, int64(r.cache.Metrics.Hits()))
	metrics.RecordCacheMiss(ctx, r.cacheType, int64(r.cache.Metrics.Misses()))
	metrics.RecordCacheHitsRatio(ctx, r.cacheType, r.cache.Metrics.Ratio())
	// Record current entries
	entriesCount := r.cache.Metrics.KeysAdded() - r.cache.Metrics.KeysEvicted()
	metrics.RecordCacheEntries(ctx, r.cacheType, int64(entriesCount))
}

func NewRistrettoCache(maxSize int, ttl time.Duration, cacheType string, logger *slog.Logger) CacheInterface {
	cache, err := ristretto.NewCache(&ristretto.Config[string, CacheEntry]{
		// NumCounters determines the number of counters (keys) to keep that hold
		// access frequency information. It's generally a good idea to have more
		// counters than the max cache capacity, as this will improve eviction
		// accuracy and subsequent hit ratios.
		NumCounters: int64(maxSize * 10),
		// The maximum total "cost" of items allowed in the cache at once.
		// MaxCost is how eviction decisions are made. For example, if MaxCost is
		// 100 and a new item with a cost of 1 increases total cache cost to 101, 1 item will be evicted.
		// MaxCost can be considered as the cache capacity, in whatever units you choose to use.
		MaxCost: int64(maxSize),
		// BufferItems determines the size of Get buffers.
		// Controls the number of keys per internal buffer used for handling concurrent Get operations.
		BufferItems: 64,
		// Metrics is true when you want variety of stats about the cache.
		Metrics: true,
	})
	if err != nil {
		logger.Error("Failed to create Ristretto cache", "error", err)
	}

	return &ristrettoCache{
		cache:     cache,
		cacheType: cacheType,
		ttl:       ttl,
		collector: newRistrettoMetricsCollector(cache, cacheType),
		logger:    logger,
	}
}

func newRistrettoMetricsCollector(cache *ristretto.Cache[string, CacheEntry], cacheType string) *ristrettoMetricsCollector {
	collector := &ristrettoMetricsCollector{
		cache:     cache,
		cacheType: cacheType,
	}

	// Start periodic collection
	go collector.startCollection()

	return collector
}
