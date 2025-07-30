package metrics

import (
	"go.opentelemetry.io/otel/metric"
)

type metrics struct {
	cacheEntries   metric.Int64Gauge
	cacheHits      metric.Int64Gauge
	cacheMisses    metric.Int64Gauge
	externalImages metric.Int64Counter
	cacheHitsRatio metric.Float64Gauge
}
