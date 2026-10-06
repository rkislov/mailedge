package metrics

import (
	"runtime"
	"sync"
	"time"
)

const (
	historySize     = 60
	sampleInterval  = 5 * time.Second
)

// Point is one dashboard sample.
type Point struct {
	TS         int64   `json:"ts"`
	Received   int64   `json:"received"`
	Delivered  int64   `json:"delivered"`
	Rejected   int64   `json:"rejected"`
	Deferred   int64   `json:"deferred"`
	Bounced    int64   `json:"bounced"`
	RecvRate   float64 `json:"recv_rate"`   // msg/s since previous sample
	DelivRate  float64 `json:"deliv_rate"`
	RejectRate float64 `json:"reject_rate"`
	CPUPercent float64 `json:"cpu_percent"` // process CPU %
	RSSBytes   uint64  `json:"rss_bytes"`
	HeapBytes  uint64  `json:"heap_bytes"`
	Goroutines int     `json:"goroutines"`
	QueueIn    int     `json:"queue_incoming"`
	QueueAct   int     `json:"queue_active"`
	QueueDef   int     `json:"queue_deferred"`
	QueueBnc   int     `json:"queue_bounce"`
}

// History keeps a ring buffer of samples for charts.
type History struct {
	mu     sync.RWMutex
	points []Point
	reg    *Registry
	queue  QueueStats
	last   counters
	lastT  time.Time
	lastCPU time.Duration
}

type counters struct {
	recv, deliv, rej, def, bnc int64
}

// QueueStats provides spool counts for sampling.
type QueueStats func() map[string]int

// NewHistory creates a sampler bound to registry.
func NewHistory(reg *Registry) *History {
	h := &History{
		points:  make([]Point, 0, historySize),
		reg:     reg,
		lastT:   time.Now(),
		lastCPU: processCPUTime(),
	}
	return h
}

// SetQueue attaches queue stats callback.
func (h *History) SetQueue(q QueueStats) { h.queue = q }

// Start begins background sampling until stop is closed.
func (h *History) Start(stop <-chan struct{}) {
	h.sample() // seed
	t := time.NewTicker(sampleInterval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				h.sample()
			}
		}
	}()
}

func (h *History) sample() {
	now := time.Now()
	cur := counters{
		recv:  h.reg.Received.Load(),
		deliv: h.reg.Delivered.Load(),
		rej:   h.reg.Rejected.Load(),
		def:   h.reg.Deferred.Load(),
		bnc:   h.reg.Bounced.Load(),
	}
	dt := now.Sub(h.lastT).Seconds()
	if dt <= 0 {
		dt = sampleInterval.Seconds()
	}
	cpuNow := processCPUTime()
	cpuPct := 0.0
	if dcpu := cpuNow - h.lastCPU; dcpu > 0 && dt > 0 {
		cpuPct = (float64(dcpu) / float64(time.Second) / dt) * 100 / float64(runtime.NumCPU())
		if cpuPct > 100 {
			cpuPct = 100
		}
		if cpuPct < 0 {
			cpuPct = 0
		}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	p := Point{
		TS:         now.Unix(),
		Received:   cur.recv,
		Delivered:  cur.deliv,
		Rejected:   cur.rej,
		Deferred:   cur.def,
		Bounced:    cur.bnc,
		RecvRate:   float64(cur.recv-h.last.recv) / dt,
		DelivRate:  float64(cur.deliv-h.last.deliv) / dt,
		RejectRate: float64(cur.rej-h.last.rej) / dt,
		CPUPercent: cpuPct,
		RSSBytes:   processRSS(),
		HeapBytes:  ms.Alloc,
		Goroutines: runtime.NumGoroutine(),
	}
	if h.queue != nil {
		if q := h.queue(); q != nil {
			p.QueueIn = q["incoming"]
			p.QueueAct = q["active"]
			p.QueueDef = q["deferred"]
			p.QueueBnc = q["bounce"]
		}
	}

	h.mu.Lock()
	h.points = append(h.points, p)
	if len(h.points) > historySize {
		h.points = h.points[len(h.points)-historySize:]
	}
	h.last = cur
	h.lastT = now
	h.lastCPU = cpuNow
	h.mu.Unlock()
}

// Snapshot returns a copy of history points (oldest→newest).
func (h *History) Snapshot() []Point {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Point, len(h.points))
	copy(out, h.points)
	return out
}

// Live is the JSON payload for the dashboard API.
type Live struct {
	Now     Point   `json:"now"`
	History []Point `json:"history"`
	Totals  map[string]int64 `json:"totals"`
}

// LivePayload builds API response.
func (h *History) LivePayload() Live {
	pts := h.Snapshot()
	var now Point
	if len(pts) > 0 {
		now = pts[len(pts)-1]
	}
	return Live{
		Now:     now,
		History: pts,
		Totals:  h.reg.Snapshot(),
	}
}
