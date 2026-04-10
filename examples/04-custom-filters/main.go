// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/filters"
)

// Example 1: Simple logging filter
func loggingFilter(headers http.Header, scope we.RequestScope) error {
	start := time.Now()

	// Store start time in request scope for use in handler
	scope.Set("start_time", start)

	// Log request details
	log.Printf("[%s] %s %s", scope.Request().Method, scope.Request().URL.Path, scope.Request().RemoteAddr)

	// Continue to next filter/handler
	return nil
}

// Example 2: Request ID filter
func requestIdFilter(headers http.Header, scope we.RequestScope) error {
	// Generate a simple request ID
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	// Add to response headers
	headers.Set("X-Request-ID", requestId)

	// Store in request scope for use by handlers
	scope.Set("request_id", requestId)

	return nil
}

// Example 3: Authentication filter (checks for API key)
func apiKeyFilter(headers http.Header, scope we.RequestScope) error {
	// applies only to /api/**
	if !strings.HasPrefix(scope.Request().URL.Path, "/api") {
		return nil
	}

	// Get API key from header
	apiKey := scope.Request().Header.Get("X-API-Key")

	// Simple validation (in production, check against database)
	if apiKey != "secret-api-key-123" {
		// Return unauthorized error to stop request processing
		return events.UnauthorizedError
	}

	// Store authenticated status
	scope.Set("authenticated", true)

	return nil
}

// Example 4: Rate limiting filter (simplified)
var requestCounts = make(map[string]int)
var lastReset = time.Now()

func rateLimitFilter(headers http.Header, scope we.RequestScope) error {
	// rate limit should only apply to path /api/rate-limited
	if scope.Request().URL.Path != "/api/rate-limited" {
		return nil
	}

	// Reset counts every minute
	if time.Since(lastReset) > time.Minute {
		requestCounts = make(map[string]int)
		lastReset = time.Now()
	}

	// Get client IP (simplified)
	ip := scope.Request().RemoteAddr

	// Increment request count
	requestCounts[ip]++

	// Check if over limit (10 requests per minute)
	if requestCounts[ip] > 10 {
		headers.Set("X-RateLimit-Limit", "10")
		headers.Set("X-RateLimit-Remaining", "0")
		return events.New(429, "Rate limit exceeded")
	}

	// Add rate limit headers
	headers.Set("X-RateLimit-Limit", "10")
	headers.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", 10-requestCounts[ip]))

	return nil
}

// Example 5: Content-Type validation filter
func contentTypeFilter(headers http.Header, scope we.RequestScope) error {
	// Only validate POST/PUT requests
	method := scope.Request().Method
	if method != "POST" && method != "PUT" {
		return nil
	}

	contentType := scope.Request().Header.Get("Content-Type")

	// Check for JSON content type
	if !strings.HasPrefix(contentType, "application/json") {
		return events.New(415, "Content-Type must be application/json")
	}

	return nil
}

func home(w http.ResponseWriter, scope we.RequestScope) error {
	requestId := scope.Get("request_id").(string)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h1>Custom Filters Example</h1>
			<p>Request ID: <code>%s</code></p>
			
			<h2>Available Endpoints</h2>
			<ul>
				<li><a href="/public">Public endpoint (no auth required)</a></li>
				<li><a href="/api/protected">Protected API (requires X-API-Key header)</a></li>
				<li><a href="/api/rate-limited">Rate limited endpoint (10 req/min)</a></li>
			</ul>
			
			<h2>Try with curl</h2>
			<pre>
# Public endpoint
curl http://localhost:8080/public

# Protected endpoint (will fail without API key)
curl http://localhost:8080/api/protected

# Protected endpoint (with API key)
curl -H "X-API-Key: secret-api-key-123" http://localhost:8080/api/protected

# Rate limited endpoint (try more than 10 times in a minute)
curl http://localhost:8080/api/rate-limited

# Test CORS preflight
curl -X OPTIONS -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     http://localhost:8080/api/data
			</pre>
		`, requestId)
	return nil
}

func public(w http.ResponseWriter, scope we.RequestScope) error {
	startTime := scope.Get("start_time").(time.Time)
	requestId := scope.Get("request_id").(string)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h1>Public Endpoint</h1>
			<p>This endpoint is accessible without authentication.</p>
			<p>Request ID: <code>%s</code></p>
			<p>Processing time: %v</p>
			<p><a href="/">Back to home</a></p>
		`, requestId, time.Since(startTime))
	return nil
}

func protected(w http.ResponseWriter, scope we.RequestScope) error {
	// First check if API key filter was applied
	authenticated := scope.Get("authenticated")
	if authenticated == nil || !authenticated.(bool) {
		return events.UnauthorizedError
	}

	requestId := scope.Get("request_id").(string)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Access granted", "request_id": "%s"}`, requestId)
	return nil
}

func rateLimited(w http.ResponseWriter, scope we.RequestScope) error {
	requestId := scope.Get("request_id").(string)
	remaining := w.Header().Get("X-RateLimit-Remaining")

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Request successful", "request_id": "%s", "remaining": %s}`,
		requestId, remaining)
	return nil
}

func data(w http.ResponseWriter, scope we.RequestScope) error {
	requestId := scope.Get("request_id").(string)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Data received", "request_id": "%s"}`, requestId)
	return nil
}

func main() {
	builder := we.New()

	// Add filters in order of execution
	// Order matters! Filters execute in the order they are added.

	// 1. Request ID - add to all requests
	builder.Filter(we.FilterFunction(requestIdFilter))

	// 2. Logging - log all requests
	builder.Filter(we.FilterFunction(loggingFilter))

	// 3. Built-in CORS filter
	corsFilter := filters.Cors().
		AllowedOrigins("http://localhost:3000", "https://example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowedHeaders("Content-Type", "X-API-Key", "Authorization").
		AllowCredentials().
		MaxAge(3600).
		Build()
	builder.Filter(corsFilter)

	// 4. Built-in Security Headers filter
	securityFilter := filters.ResponseHeaders().
		HSTS(31536000, true, false). // 1 year, includeSubDomains, no preload
		FrameOptions(filters.FrameOptionDeny).
		NoSniff().
		ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin).
		Build()
	builder.Filter(securityFilter)

	// Home page - no special filters needed
	builder.Handle("/", home)

	// Public endpoint - accessible without authentication
	builder.Handle("/public", public)

	// Rate-limited endpoint
	builder.Filter(we.FilterFunction(rateLimitFilter)). // filter itself checks path, but we add it here for clarity
								Handle("/api/rate-limited", rateLimited)

	// Protected API endpoint - requires API key
	// We'll create a custom filter chain for /api/** paths. Note that it will also affect the rate-limited endpoint,
	// but if rate limit is reached, rate limit filter should return first..
	builder.Filter(we.FilterFunction(apiKeyFilter)). // filter itself checks path, but we add it here for clarity
								Handle("/api/protected", protected)

	// Note: For a real app with path-based filters, you'd use the security package
	// See example 10-authorization for proper path-based filtering

	// Endpoint handling POST requests to trigger content type filer
	builder.Filter(we.FilterFunction(contentTypeFilter)).
		HandleMethod("POST", "/api/data", data)

	log.Println("Server starting on http://localhost:8080")
	log.Println("API Key for protected endpoints: secret-api-key-123")
	log.Println("Rate limit: 10 requests per minute per IP")
	log.Println("Press Ctrl+C to stop")

	engine := builder.Build()

	if err := engine.Listen(":8080"); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}
