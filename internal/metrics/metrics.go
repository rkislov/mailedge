package metrics

import (
	"sync/atomic"
)

// Registry is a minimal metrics holder for Stage 1 (Prometheus later).
type Registry struct {
	Received  atomic.Int64
	Delivered atomic.Int64
	Deferred  atomic.Int64
	Rejected  atomic.Int64
	Bounced   atomic.Int64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{}
}

// Snapshot returns current counter values.
func (r *Registry) Snapshot() map[string]int64 {
	return map[string]int64{
		"smtp_received_total":   r.Received.Load(),
		"smtp_delivered_total":  r.Delivered.Load(),
		"smtp_deferred_total":   r.Deferred.Load(),
		"smtp_rejected_total":   r.Rejected.Load(),
		"smtp_bounced_total":    r.Bounced.Load(),
	}
}
