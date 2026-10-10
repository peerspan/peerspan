package coord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/relay"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

// Operations: the loopback ops listener (health and Prometheus metrics) and
// JSON logs. Neither metric labels nor logs carry client addresses, and
// metric labels carry no network, host, or person IDs.

// Version is the build's version string, set with -ldflags -X.
var Version = "dev"

// ErrOpsNotLoopback refuses an ops address that is not a loopback literal.
var ErrOpsNotLoopback = errors.New("--ops-listen must be a loopback address")

// CheckOpsAddress accepts HOST:PORT only when HOST is an IP literal in
// 127.0.0.0/8 or ::1.
func CheckOpsAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrOpsNotLoopback
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" || !(addr.Is4() && addr.IsLoopback() || addr == netip.IPv6Loopback()) {
		return ErrOpsNotLoopback
	}
	return nil
}

const logTime = "2006-01-02T15:04:05.000000Z"

// NewLogger writes one JSON object per line with time (UTC, fractional
// seconds), level (info or error), and msg.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 {
			switch a.Key {
			case slog.TimeKey:
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(logTime))
			case slog.LevelKey:
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			}
		}
		return a
	}}))
}

// LogError writes an error line: message describes the failure for the
// operator, and network and host are added when known.
func LogError(log *slog.Logger, message, network, host string) {
	attrs := []slog.Attr{slog.String("error", message)}
	if network != "" {
		attrs = append(attrs, slog.String("network", network))
	}
	if host != "" {
		attrs = append(attrs, slog.String("host", host))
	}
	log.LogAttrs(context.Background(), slog.LevelError, "error", attrs...)
}

func (s *Server) logError(message string, err error, network, host string) {
	LogError(s.Log, message+": "+err.Error(), network, host)
}

// httpErrorLog replaces http.Server's own log, whose lines can include client
// addresses, with an error line that withholds the details.
func (s *Server) httpErrorLog() *log.Logger {
	return log.New(writerFunc(func(p []byte) (int, error) {
		LogError(s.Log, "the HTTP server reported a connection or handler error; details are withheld because they can include client addresses", "", "")
		return len(p), nil
	}), "", 0)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// requestBuckets are Prometheus's default histogram buckets, in seconds.
var requestBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

type histogram struct {
	counts []uint64 // per bucket, not cumulative; the last is +Inf
	sum    float64
	count  uint64
}

type requestKey struct {
	route string
	code  int
}

// metrics holds the counters; gauges are read at scrape time.
type metrics struct {
	mu        sync.Mutex
	requests  map[requestKey]uint64
	durations map[string]*histogram
	refusals  map[string]uint64

	relayBytes atomic.Uint64
	notified   atomic.Uint64
}

func newMetrics() *metrics {
	return &metrics{requests: map[requestKey]uint64{}, durations: map[string]*histogram{},
		refusals: map[string]uint64{limitMembers: 0, limitNetworksPerIP: 0, limitRelayBytes: 0}}
}

func (m *metrics) request(route string, code int, elapsed time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestKey{route, code}]++
	h := m.durations[route]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(requestBuckets)+1)}
		m.durations[route] = h
	}
	seconds := elapsed.Seconds()
	i := sort.SearchFloat64s(requestBuckets, seconds)
	h.counts[i]++
	h.sum += seconds
	h.count++
}

func (m *metrics) refused(limit string) {
	m.mu.Lock()
	m.refusals[limit]++
	m.mu.Unlock()
}

// requestRecorder observes one coordination API request: its status and any
// error given to respond.
type requestRecorder struct {
	http.ResponseWriter
	status int
	err    error
}

func (r *requestRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *requestRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// recordError hands respond's error to the request's recorder, through any
// wrapping writers.
func recordError(w http.ResponseWriter, err error) {
	for w != nil {
		if r, ok := w.(*requestRecorder); ok {
			r.err = err
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// routeOf is a mux pattern without its method, or other when nothing matched.
func routeOf(pattern string) string {
	if pattern == "" {
		return "other"
	}
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return path
	}
	return pattern
}

// networkOf is the path segment at the route's {network} wildcard.
func networkOf(route, path string) string {
	routeParts, pathParts := strings.Split(route, "/"), strings.Split(path, "/")
	for i, part := range routeParts {
		if part == "{network}" && i < len(pathParts) {
			return pathParts[i]
		}
	}
	return ""
}

// observe counts, times, and logs each coordination API request after its
// response.
func (s *Server) observe(mux *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		_, pattern := mux.Handler(r)
		route := routeOf(pattern)
		recorder := &requestRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		elapsed := time.Since(start)
		s.metrics.request(route, recorder.status, elapsed)
		network, host := "", ""
		if route != "other" {
			network = networkOf(route, r.URL.Path)
		}
		if r.TLS != nil {
			if public, err := tlsid.PeerKey(*r.TLS); err == nil {
				host = membership.HostID(public)
			}
		}
		s.hosts.record(s.requestSequence(r.Context()), host, time.Now())
		var limited *limitError
		if errors.As(recorder.err, &limited) {
			s.metrics.refused(limited.limit)
		} else if recorder.err != nil && recorder.status == http.StatusInternalServerError {
			s.logError("a coordination API request failed with an internal error", recorder.err, network, host)
		}
		attrs := []slog.Attr{slog.String("method", r.Method), slog.String("route", route), slog.Int("status", recorder.status), slog.Float64("duration_ms", milliseconds(elapsed))}
		if network != "" {
			attrs = append(attrs, slog.String("network", network))
		}
		if host != "" {
			attrs = append(attrs, slog.String("host", host))
		}
		s.Log.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
	})
}

func milliseconds(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())) / 1000
}

// OpsHandler serves GET /healthz and GET /metrics; nothing else.
func (s *Server) OpsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var serve func(http.ResponseWriter, *http.Request)
		switch r.URL.Path {
		case "/healthz":
			serve = s.serveHealth
		case "/metrics":
			serve = s.serveMetrics
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		serve(w, r)
	})
}

// ServeOps serves the ops listener until ctx is cancelled.
func (s *Server) ServeOps(ctx context.Context, listener net.Listener) error {
	server := &http.Server{Handler: s.OpsHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: s.httpErrorLog()}
	stop := context.AfterFunc(ctx, func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(shutdownCtx) != nil {
			_ = server.Close()
		}
	})
	defer stop()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	status, code := "ok", http.StatusOK
	var one int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM identity WHERE singleton = 1`).Scan(&one); err != nil {
		status, code = "unavailable", http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		ID     string `json:"id"`
	}{status, s.identity.ID})
}

func (s *Server) countRows(ctx context.Context, query string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var n int64
	err := s.db.QueryRowContext(ctx, query).Scan(&n)
	return n, err
}

// serveMetrics writes the Prometheus text exposition format, version 0.0.4.
// Gauges that need the database are left out when it cannot be read.
func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	family := func(name, kind, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	family("capsule_coord_info", "gauge", "The build's version, always 1.")
	fmt.Fprintf(&b, "capsule_coord_info{version=%s} 1\n", labelValue(Version))
	for _, gauge := range []struct{ name, help, query string }{
		{"capsule_coord_networks", "Registered networks.", `SELECT COUNT(*) FROM networks`},
		{"capsule_coord_member_hosts", "Current member hosts across networks, excluding revoked and departed hosts.", `SELECT COUNT(*) FROM members`},
	} {
		n, err := s.countRows(r.Context(), gauge.query)
		if err != nil {
			s.logError("a metrics scrape could not read the database", err, "", "")
			continue
		}
		family(gauge.name, "gauge", gauge.help)
		fmt.Fprintf(&b, "%s %d\n", gauge.name, n)
	}
	family("capsule_coord_relay_connections", "gauge", "Open relay connections, by negotiated ALPN.")
	conns := s.relay.connections()
	for _, alpn := range []string{relay.ALPN, relay.ALPNv2} {
		fmt.Fprintf(&b, "capsule_coord_relay_connections{alpn=%s} %d\n", labelValue(alpn), conns[alpn])
	}

	m := s.metrics
	m.mu.Lock()
	family("capsule_coord_requests_total", "counter", "Coordination API requests by route template and HTTP status.")
	keys := make([]requestKey, 0, len(m.requests))
	for key := range m.requests {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].route < keys[j].route || keys[i].route == keys[j].route && keys[i].code < keys[j].code
	})
	for _, key := range keys {
		fmt.Fprintf(&b, "capsule_coord_requests_total{route=%s,code=\"%d\"} %d\n", labelValue(key.route), key.code, m.requests[key])
	}
	family("capsule_coord_request_seconds", "histogram", "Coordination API request duration by route template.")
	routes := make([]string, 0, len(m.durations))
	for route := range m.durations {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		h, label := m.durations[route], labelValue(route)
		var cumulative uint64
		for i, upper := range requestBuckets {
			cumulative += h.counts[i]
			fmt.Fprintf(&b, "capsule_coord_request_seconds_bucket{route=%s,le=\"%s\"} %d\n", label, formatFloat(upper), cumulative)
		}
		fmt.Fprintf(&b, "capsule_coord_request_seconds_bucket{route=%s,le=\"+Inf\"} %d\n", label, h.count)
		fmt.Fprintf(&b, "capsule_coord_request_seconds_sum{route=%s} %s\n", label, formatFloat(h.sum))
		fmt.Fprintf(&b, "capsule_coord_request_seconds_count{route=%s} %d\n", label, h.count)
	}
	family("capsule_coord_limit_refusals_total", "counter", "Refusals with 429 and dropped relay frames, by limit.")
	limits := make([]string, 0, len(m.refusals))
	for limit := range m.refusals {
		limits = append(limits, limit)
	}
	sort.Strings(limits)
	for _, limit := range limits {
		fmt.Fprintf(&b, "capsule_coord_limit_refusals_total{limit=%s} %d\n", labelValue(limit), m.refusals[limit])
	}
	m.mu.Unlock()
	family("capsule_coord_identity_hosts", "gauge", "Distinct hosts that completed a request or opened a relay connection through each identity's listener in the last 24 hours.")
	seen := s.hosts.counts(time.Now())
	for _, sequence := range s.sortedSequences() {
		fmt.Fprintf(&b, "capsule_coord_identity_hosts{sequence=\"%d\"} %d\n", sequence, seen[sequence])
	}
	family("capsule_coord_relay_bytes_total", "counter", "Relayed datagram bytes, as counted for --relay-bytes-per-month.")
	fmt.Fprintf(&b, "capsule_coord_relay_bytes_total %d\n", m.relayBytes.Load())
	family("capsule_coord_changes_notified_total", "counter", "Changed frames sent.")
	fmt.Fprintf(&b, "capsule_coord_changes_notified_total %d\n", m.notified.Load())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = io.WriteString(w, b.String())
}

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// labelValue quotes a label value with the exposition format's escapes.
func labelValue(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
}
