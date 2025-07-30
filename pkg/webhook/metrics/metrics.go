package metrics

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const name = "github.com/firebolt-db/firebolt-auror"

var m *metrics

func InitMetrics(ctx context.Context) error {
	meter := otel.Meter(name)
	var err error

	m = &metrics{}

	// Initialize cache entries gauge
	if m.cacheEntries, err = meter.Int64Gauge("cache_entries",
		metric.WithDescription("Number of entries in each cache"),
		metric.WithUnit("{entries}")); err != nil {
		return err
	}

	// Initialize cache misses gauge
	if m.cacheMisses, err = meter.Int64Gauge("cache_misses_total",
		metric.WithDescription("Total number of cache misses"),
		metric.WithUnit("{misses}")); err != nil {
		return err
	}

	// Initialize cache hits gauge
	if m.cacheHits, err = meter.Int64Gauge("cache_hits_total",
		metric.WithDescription("Total number of cache hits"),
		metric.WithUnit("{hits}")); err != nil {
		return err
	}

	// Initialize external images counter
	if m.externalImages, err = meter.Int64Counter("external_images_total",
		metric.WithDescription("Total number of external images encountered"),
		metric.WithUnit("{images}")); err != nil {
		return err
	}

	// Initialize cache hits ratio gauge
	if m.cacheHitsRatio, err = meter.Float64Gauge("cache_hits_ratio",
		metric.WithDescription("Ratio of cache hits to total cache operations"),
		metric.WithUnit("{ratio}")); err != nil {
		return err
	}
	return nil
}

func RecordCacheEntries(ctx context.Context, cacheType string, entriesCount int64) {
	if m == nil {
		return
	}
	m.cacheEntries.Record(ctx, entriesCount,
		metric.WithAttributes(attribute.String("cache_type", cacheType)))
}

func RecordCacheHit(ctx context.Context, cacheType string, hits int64) {
	if m == nil {
		return
	}
	m.cacheHits.Record(ctx, hits,
		metric.WithAttributes(
			attribute.String("cache_type", cacheType)))
}

func RecordCacheMiss(ctx context.Context, cacheType string, misses int64) {
	if m == nil {
		return
	}
	m.cacheMisses.Record(ctx, misses,
		metric.WithAttributes(attribute.String("cache_type", cacheType)))
}

func RecordCacheHitsRatio(ctx context.Context, cacheType string, hitsRatio float64) {
	if m == nil {
		return
	}
	m.cacheHitsRatio.Record(ctx, hitsRatio,
		metric.WithAttributes(attribute.String("cache_type", cacheType)))
}

func RecordExternalImage(ctx context.Context, namespace, kind, name string) {
	if m == nil {
		return
	}

	m.externalImages.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("namespace", namespace),
			attribute.String("kind", kind),
			attribute.String("name", name),
		))
}
