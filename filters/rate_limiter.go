// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package filters

import (
	"net"
	"net/http"
	"sync"
	"time"

	we "github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

const (
	// DefaultRateLimitRequestsPerSecond is the default rate limit (requests per second)
	DefaultRateLimitRequestsPerSecond = 100
	// DefaultRateLimitBurst is the default burst size
	DefaultRateLimitBurst = 20
)

// RateLimiterBuilder defines the builder interface for configuring rate limiting
type RateLimiterBuilder interface {
	// RequestsPerSecond sets the rate limit in requests per second (default: 100)
	RequestsPerSecond(rps int) RateLimiterBuilder
	// Burst sets the maximum burst size (default: 20)
	Burst(size int) RateLimiterBuilder
	// ExemptPaths adds paths that bypass rate limiting (e.g., health checks)
	ExemptPaths(paths ...string) RateLimiterBuilder
	// Identifier allows custom identifier extraction (default: client IP)
	// Common implementations: user ID from session, API key from header, etc.
	Identifier(fn func(scope we.RequestScope) string) RateLimiterBuilder
	// Build creates the configured rate limiter filter
	Build() we.Filter
}

// tokenBucket represents a token bucket for rate limiting
type tokenBucket struct {
	tokens   float64   // Current number of tokens
	lastFill time.Time // Last time the bucket was filled
	mu       sync.Mutex
}

// rateLimiter implements rate limiting using the token bucket algorithm
type rateLimiter struct {
	rps            int                                // Requests per second
	burst          int                                // Maximum tokens in bucket
	exemptPaths    map[string]bool                    // Paths that bypass rate limiting
	buckets        map[string]*tokenBucket            // Per-identifier token buckets
	mu             sync.RWMutex                       // Protects buckets map
	identifierFunc func(scope we.RequestScope) string // Function to extract identifier from request
	cleanupTicker  *time.Ticker                       // Periodic cleanup of stale buckets
	done           chan struct{}                      // Signal to stop cleanup goroutine
}

// Filter implements the we.Filter interface
func (rl *rateLimiter) Filter(header http.Header, scope we.RequestScope) error {
	request := scope.Request()

	// Check if path is exempted
	if rl.exemptPaths[request.URL.Path] {
		return nil
	}

	// Get identifier for this request
	identifier := rl.identifierFunc(scope)

	// Get or create token bucket for this identifier
	bucket := rl.getBucket(identifier)

	// Try to consume a token
	if !rl.consumeToken(bucket) {
		// Rate limit exceeded
		return events.TooManyRequestsError.WithPayload(
			"text/plain",
			[]byte("Rate limit exceeded"),
		)
	}

	return nil
}

// getBucket returns the token bucket for the given identifier, creating it if necessary
func (rl *rateLimiter) getBucket(identifier string) *tokenBucket {
	rl.mu.RLock()
	bucket, exists := rl.buckets[identifier]
	rl.mu.RUnlock()

	if exists {
		return bucket
	}

	// Create new bucket
	rl.mu.Lock()
	// Check again in case another goroutine created it
	if bucket, exists := rl.buckets[identifier]; exists {
		rl.mu.Unlock()
		return bucket
	}

	bucket = &tokenBucket{
		tokens:   float64(rl.burst),
		lastFill: time.Now(),
	}
	rl.buckets[identifier] = bucket
	rl.mu.Unlock()

	return bucket
}

// consumeToken attempts to consume one token from the bucket
func (rl *rateLimiter) consumeToken(bucket *tokenBucket) bool {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill bucket based on time elapsed
	now := time.Now()
	elapsed := now.Sub(bucket.lastFill).Seconds()
	tokensToAdd := elapsed * float64(rl.rps)

	if tokensToAdd > 0 {
		bucket.tokens = min(float64(rl.burst), bucket.tokens+tokensToAdd)
		bucket.lastFill = now
	}

	// Try to consume a token
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}

	return false
}

// cleanupStaleaBuckets removes buckets that haven't been used recently
func (rl *rateLimiter) cleanupStaleBuckets() {
	ticker := time.NewTicker(1 * time.Minute)
	rl.cleanupTicker = ticker

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for identifier, bucket := range rl.buckets {
				bucket.mu.Lock()
				// Remove buckets that haven't been used in the last 10 minutes
				if now.Sub(bucket.lastFill) > 10*time.Minute {
					delete(rl.buckets, identifier)
				}
				bucket.mu.Unlock()
			}
			rl.mu.Unlock()

		case <-rl.done:
			ticker.Stop()
			return
		}
	}
}

// Stop stops the rate limiter and cleans up resources
func (rl *rateLimiter) Stop() {
	close(rl.done)
}

// defaultIdentifier extracts the client IP address from the request
func defaultIdentifier(scope we.RequestScope) string {
	request := scope.Request()

	// Try X-Forwarded-For header first (for proxied requests)
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		if ip, _, err := net.SplitHostPort(xff); err == nil {
			return ip
		}
		return xff
	}

	// Try X-Real-IP header
	if xri := request.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	if ip, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		return ip
	}

	return request.RemoteAddr
}

// rateLimiterBuilder is the implementation of RateLimiterBuilder
type rateLimiterBuilder struct {
	filter *rateLimiter
}

// RequestsPerSecond sets the rate limit
func (rlb *rateLimiterBuilder) RequestsPerSecond(rps int) RateLimiterBuilder {
	if rps <= 0 {
		panic("requests per second must be greater than 0")
	}
	rlb.filter.rps = rps
	return rlb
}

// Burst sets the maximum burst size
func (rlb *rateLimiterBuilder) Burst(size int) RateLimiterBuilder {
	if size <= 0 {
		panic("burst size must be greater than 0")
	}
	rlb.filter.burst = size
	return rlb
}

// ExemptPaths adds paths that bypass rate limiting
func (rlb *rateLimiterBuilder) ExemptPaths(paths ...string) RateLimiterBuilder {
	if len(paths) == 0 {
		panic("at least one path must be provided")
	}
	for _, path := range paths {
		if path == "" {
			panic("path cannot be empty")
		}
		rlb.filter.exemptPaths[path] = true
	}
	return rlb
}

// Identifier sets a custom identifier function
func (rlb *rateLimiterBuilder) Identifier(fn func(scope we.RequestScope) string) RateLimiterBuilder {
	if fn == nil {
		panic("identifier function cannot be nil")
	}
	rlb.filter.identifierFunc = fn
	return rlb
}

// Build creates the configured rate limiter
func (rlb *rateLimiterBuilder) Build() we.Filter {
	// Start cleanup goroutine
	go rlb.filter.cleanupStaleBuckets()
	return rlb.filter
}

// RateLimiter creates a new RateLimiterBuilder with default configuration.
// Default configuration:
// - Requests per second: 100
// - Burst size: 20
// - Identifier: Client IP address (with X-Forwarded-For support)
//
// Example:
//
//	filter := filters.RateLimiter().
//	    RequestsPerSecond(50).
//	    Burst(10).
//	    ExemptPaths("/health", "/metrics").
//	    Build()
//
//	engine := we.New().
//	    Filter(filter).
//	    Build()
func RateLimiter() RateLimiterBuilder {
	done := make(chan struct{})
	return &rateLimiterBuilder{
		filter: &rateLimiter{
			rps:            DefaultRateLimitRequestsPerSecond,
			burst:          DefaultRateLimitBurst,
			exemptPaths:    make(map[string]bool),
			buckets:        make(map[string]*tokenBucket),
			identifierFunc: defaultIdentifier,
			done:           done,
		},
	}
}

// min returns the minimum of two integers
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
