// Package metrics defines all Prometheus metric collectors for the goauth server.
// Metrics are registered against a dedicated Registry (not the default global one)
// so tests can use separate registries without collision.
//
// The package auto-initialises itself via init() so that metrics are available
// as soon as the package is imported — even in unit tests that do not call
// Init() explicitly.  Calling Init() from main() is idempotent (no-op if
// already initialised).
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Registry is a dedicated Prometheus registry for the application. It is
// initialised once (via init on import) and is used by the /metrics handler
// to serve only application-level metrics.
var Registry *prometheus.Registry

// HTTP request metrics.
var (
	// HTTPRequestsTotal counts all HTTP requests, labelled by HTTP method,
	// URL pattern (path template), and response status code.
	HTTPRequestsTotal *prometheus.CounterVec

	// HTTPRequestDuration measures the latency of each HTTP request as a
	// histogram with exponential buckets from 5 ms to 10 s.
	HTTPRequestDuration *prometheus.HistogramVec
)

// Business-level metrics.
var (
	// TokensIssuedTotal counts successfully issued access tokens.
	TokensIssuedTotal prometheus.Counter

	// TokenRevocationsTotal counts explicitly revoked access tokens.
	TokenRevocationsTotal prometheus.Counter

	// AuthFailuresTotal counts failed authentication attempts, labelled by
	// reason (missing_token, malformed_header, invalid_token, revoked_token).
	AuthFailuresTotal *prometheus.CounterVec

	// RateLimitViolationsTotal counts requests rejected by rate limiting,
	// labelled by limiter_type (ip, user).
	RateLimitViolationsTotal *prometheus.CounterVec

	// CSRFViolationsTotal counts requests rejected by CSRF validation.
	CSRFViolationsTotal prometheus.Counter

	// AdminAccessDeniedTotal counts requests rejected by the admin middleware.
	AdminAccessDeniedTotal prometheus.Counter
)

var once sync.Once

// init ensures metrics are ready as soon as the package is imported so that
// middleware and handlers can reference the variables without an explicit
// Init() call (e.g. in unit tests).
func init() {
	once.Do(setup)
}

// Init (re-)initialises the metrics registry.  Calling it from main() is
// the recommended pattern because it makes the initialisation explicit.
// If the package init() has already run, this is a no-op.
func Init() {
	once.Do(setup)
}

// setup creates all metric collectors and registers them against a fresh
// dedicated Registry.  It is called at most once per process lifetime.
func setup() {
	Registry = prometheus.NewRegistry()

	// Standard Go runtime and OS process metrics.
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// ── HTTP metrics ──────────────────────────────────────────────────────
	HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "goauth",
		Subsystem: "http",
		Name:      "requests_total",
		Help:      "Total number of HTTP requests, partitioned by method, path, and status code.",
	}, []string{"method", "path", "status_code"})

	HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "goauth",
		Subsystem: "http",
		Name:      "request_duration_seconds",
		Help:      "HTTP request duration in seconds, partitioned by method and path.",
		Buckets:   prometheus.ExponentialBucketsRange(0.005, 10, 12),
	}, []string{"method", "path"})

	// ── Business metrics ──────────────────────────────────────────────────
	TokensIssuedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goauth",
		Name:      "tokens_issued_total",
		Help:      "Total number of access tokens successfully issued.",
	})

	TokenRevocationsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goauth",
		Name:      "token_revocations_total",
		Help:      "Total number of access tokens explicitly revoked.",
	})

	AuthFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "goauth",
		Name:      "auth_failures_total",
		Help:      "Total number of authentication failures, partitioned by reason.",
	}, []string{"reason"})

	RateLimitViolationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "goauth",
		Name:      "rate_limit_violations_total",
		Help:      "Total number of requests rejected by rate limiting, partitioned by limiter type.",
	}, []string{"limiter_type"})

	CSRFViolationsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goauth",
		Name:      "csrf_violations_total",
		Help:      "Total number of requests rejected by CSRF validation.",
	})

	AdminAccessDeniedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "goauth",
		Name:      "admin_access_denied_total",
		Help:      "Total number of requests rejected by the admin authorization check.",
	})

	Registry.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		TokensIssuedTotal,
		TokenRevocationsTotal,
		AuthFailuresTotal,
		RateLimitViolationsTotal,
		CSRFViolationsTotal,
		AdminAccessDeniedTotal,
	)
}
