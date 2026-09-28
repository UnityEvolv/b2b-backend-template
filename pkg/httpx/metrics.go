package httpx

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Service metrics (UO-49): request rate, latency, errors and the process's
// own resource use, kept in memory and served in the Prometheus text format
// at /metrics. Cloud Run's built-in metrics cover the same ground in the
// cloud; these are what a laptop, or a scraping sidecar, reads.

// latencyBuckets are the request latency histogram's upper bounds, seconds.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type routeKey struct {
	method, route string
	status        int
}

type histogram struct {
	counts []uint64
	sum    float64
	count  uint64
}

type metrics struct {
	mu       sync.Mutex
	requests map[routeKey]uint64
	latency  map[string]*histogram // by method and route
	inFlight atomic.Int64
	started  time.Time
}

var serviceMetrics = &metrics{requests: map[routeKey]uint64{}, latency: map[string]*histogram{}, started: time.Now()}

func (m *metrics) observe(method, route string, status int, d time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[routeKey{method, route, status}]++
	key := method + " " + route
	h := m.latency[key]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(latencyBuckets))}
		m.latency[key] = h
	}
	s := d.Seconds()
	for i, b := range latencyBuckets {
		if s <= b {
			h.counts[i]++
		}
	}
	h.sum += s
	h.count++
}

func label(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", ` `).Replace(s) }

// write is every metric in the Prometheus text exposition format.
func (m *metrics) write(w *strings.Builder) {
	m.mu.Lock()
	keys := make([]routeKey, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].status < keys[j].status
	})
	w.WriteString("# HELP http_requests_total Requests served, by route and status.\n# TYPE http_requests_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(w, "http_requests_total{method=%q,route=%q,status=\"%d\"} %d\n", label(k.method), label(k.route), k.status, m.requests[k])
	}
	w.WriteString("# HELP http_request_duration_seconds Request latency.\n# TYPE http_request_duration_seconds histogram\n")
	routes := make([]string, 0, len(m.latency))
	for r := range m.latency {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, r := range routes {
		method, route, _ := strings.Cut(r, " ")
		h := m.latency[r]
		for i, b := range latencyBuckets {
			fmt.Fprintf(w, "http_request_duration_seconds_bucket{method=%q,route=%q,le=\"%s\"} %d\n", label(method), label(route), strconv.FormatFloat(b, 'f', -1, 64), h.counts[i])
		}
		fmt.Fprintf(w, "http_request_duration_seconds_bucket{method=%q,route=%q,le=\"+Inf\"} %d\n", label(method), label(route), h.count)
		fmt.Fprintf(w, "http_request_duration_seconds_sum{method=%q,route=%q} %g\n", label(method), label(route), h.sum)
		fmt.Fprintf(w, "http_request_duration_seconds_count{method=%q,route=%q} %d\n", label(method), label(route), h.count)
	}
	m.mu.Unlock()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	fmt.Fprintf(w, "# HELP http_requests_in_flight Requests being served now.\n# TYPE http_requests_in_flight gauge\nhttp_requests_in_flight %d\n", m.inFlight.Load())
	fmt.Fprintf(w, "# HELP process_goroutines Goroutines running.\n# TYPE process_goroutines gauge\nprocess_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP process_heap_bytes Heap in use.\n# TYPE process_heap_bytes gauge\nprocess_heap_bytes %d\n", mem.HeapInuse)
	fmt.Fprintf(w, "# HELP process_memory_bytes Memory obtained from the system.\n# TYPE process_memory_bytes gauge\nprocess_memory_bytes %d\n", mem.Sys)
	fmt.Fprintf(w, "# HELP process_gc_pause_seconds_total Time spent in garbage collection pauses.\n# TYPE process_gc_pause_seconds_total counter\nprocess_gc_pause_seconds_total %g\n", float64(mem.PauseTotalNs)/1e9)
	fmt.Fprintf(w, "# HELP process_uptime_seconds Time since start.\n# TYPE process_uptime_seconds gauge\nprocess_uptime_seconds %g\n", time.Since(m.started).Seconds())
}

// metricsHandler serves /metrics to whatever scrapes the service directly.
// A request that came through the load balancer carries a forwarding
// header and is refused: route names are not for the internet.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-For") != "" {
		http.NotFound(w, r)
		return
	}
	var b strings.Builder
	serviceMetrics.write(&b)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
