// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/filters"
)

// home handler - returns a simple HTML page with links to the other endpoints
func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Rate Limiting Example</title></head>
<body>
    <h1>Rate Limiting Example</h1>
    <p>This server allows <strong>2 requests per second</strong> with a burst of <strong>3</strong>.</p>
    <ul>
        <li><a href="/">Home</a> (rate limited)</li>
        <li><a href="/api/data">API Data</a> (rate limited)</li>
        <li><a href="/health">Health Check</a> (exempt from rate limiting)</li>
    </ul>
    <p>Try rapidly refreshing this page to trigger a <code>429 Too Many Requests</code> response.</p>
</body>
</html>`)
	return nil
}

// apiData handler - returns JSON data, subject to rate limiting
func apiData(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"status":"ok","data":["item1","item2","item3"]}`)
	return nil
}

// healthCheck handler - exempt from rate limiting, always accessible
func healthCheck(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"status":"healthy"}`)
	return nil
}

func main() {
	// Create a rate limiter filter using the token bucket algorithm.
	//
	// The token bucket works as follows:
	// - A bucket holds up to "burst" tokens (here 3).
	// - Tokens are added at a rate of "RequestsPerSecond" (here 2 per second).
	// - Each request consumes one token. If no tokens remain, the request
	//   is rejected with HTTP 429 Too Many Requests.
	// - The burst value allows short spikes above the sustained rate: a client
	//   can make up to 3 rapid requests before being throttled.
	//
	// Rate limiting is applied per client IP address by default.
	rateLimiter := filters.RateLimiter().
		RequestsPerSecond(2). // Low rate for easy testing (default: 100)
		Burst(3).             // Allow a short burst of 3 requests (default: 20)
		ExemptPaths("/health").
		Build()

	// Build the engine with the rate limiter filter and route handlers
	engine := we.New().
		Filter(rateLimiter).
		HandleMethod("GET", "/", home).
		HandleMethod("GET", "/api/data", apiData).
		HandleMethod("GET", "/health", healthCheck).
		Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Rate limit: 2 requests/second, burst: 3")
	fmt.Println("Exempt paths: /health")
	fmt.Println("Press Ctrl+C to stop")

	// To test rate limiting, run:
	//   for i in $(seq 1 10); do curl -w " HTTP %{http_code}\n" http://localhost:8080/; done
	// The first 3 requests succeed (burst), then requests are throttled to 2/sec.
	// Health checks always succeed:
	//   for i in $(seq 1 10); do curl -w " HTTP %{http_code}\n" http://localhost:8080/health; done

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
