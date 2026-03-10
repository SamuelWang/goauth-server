package middleware

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Per-minute rate limits applied to specific route groups.
const (
	// TokenRatePerMin is the maximum number of token exchange requests per minute per IP.
	TokenRatePerMin = 10
	// AuthRatePerMin is the maximum number of authorization initiation requests per minute per IP.
	AuthRatePerMin = 20
	// AdminRatePerMin is the maximum number of admin API requests per minute per authenticated user.
	AdminRatePerMin = 30
)

// limiterEntry pairs a rate.Limiter with its last-seen timestamp so stale
// entries can be purged by the background cleanup goroutine.
type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// keyedLimiter maps arbitrary string keys (IP addresses or user IDs) to
// individual rate.Limiters.  A background goroutine removes entries that have
// not been accessed for at least ttl to bound memory growth.
type keyedLimiter struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	r       rate.Limit
	burst   int
	ttl     time.Duration
}

func newKeyedLimiter(r rate.Limit, burst int, ttl time.Duration) *keyedLimiter {
	kl := &keyedLimiter{
		entries: make(map[string]*limiterEntry),
		r:       r,
		burst:   burst,
		ttl:     ttl,
	}
	go kl.cleanup()
	return kl
}

func (kl *keyedLimiter) getLimiter(key string) *rate.Limiter {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	entry, ok := kl.entries[key]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(kl.r, kl.burst)}
		kl.entries[key] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// cleanup runs in the background and removes stale entries every ttl interval.
func (kl *keyedLimiter) cleanup() {
	ticker := time.NewTicker(kl.ttl)
	defer ticker.Stop()
	for range ticker.C {
		kl.mu.Lock()
		for key, entry := range kl.entries {
			if time.Since(entry.lastSeen) > kl.ttl {
				delete(kl.entries, key)
			}
		}
		kl.mu.Unlock()
	}
}

// retryAfterSeconds returns how many whole seconds the caller should wait
// before the next token becomes available.
func retryAfterSeconds(l *rate.Limiter) string {
	r := l.Reserve()
	d := r.Delay()
	r.Cancel()
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// RateLimitByIP returns a Gin middleware that enforces a per-IP rate limit.
// perMin is the sustained request rate in requests per minute; burst is the
// maximum instantaneous burst size.  Exceeding the limit yields HTTP 429 with
// a Retry-After header.
func RateLimitByIP(perMin int, burst int) gin.HandlerFunc {
	r := rate.Limit(float64(perMin) / 60.0)
	kl := newKeyedLimiter(r, burst, 5*time.Minute)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := kl.getLimiter(ip)

		if !limiter.Allow() {
			c.Header("Retry-After", retryAfterSeconds(limiter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_requests",
				"error_description": "rate limit exceeded, please slow down",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByUser returns a Gin middleware that enforces a per-authenticated-user
// rate limit.  It must run after AuthMiddleware so that "user_id" is present in
// the Gin context.  When "user_id" is absent the middleware falls back to a
// per-IP limit so unauthenticated requests to admin routes are still bounded.
// perMin is the sustained rate in requests per minute; burst is the maximum
// instantaneous burst size.
func RateLimitByUser(perMin int, burst int) gin.HandlerFunc {
	r := rate.Limit(float64(perMin) / 60.0)
	kl := newKeyedLimiter(r, burst, 5*time.Minute)

	return func(c *gin.Context) {
		var key string
		if userID, exists := c.Get("user_id"); exists {
			key = "user:" + userID.(string)
		} else {
			key = "ip:" + c.ClientIP()
		}

		limiter := kl.getLimiter(key)

		if !limiter.Allow() {
			c.Header("Retry-After", retryAfterSeconds(limiter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_requests",
				"error_description": "rate limit exceeded, please slow down",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
