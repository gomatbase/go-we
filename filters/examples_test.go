// Copyright 2026 GOM. All rights reserved.
// Since 01/04/2026 By GOM
// Licensed under MIT License

package filters_test

import (
	"fmt"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/filters"
)

// Example_corsBasic demonstrates basic CORS configuration for specific origins
func Example_corsBasic() {
	engine := we.New()

	// Configure CORS to allow specific origins
	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com", "https://app.example.com").
		AllowedMethods("GET", "POST").
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured for specific origins")
	// Output: CORS filter configured for specific origins
}

// Example_corsWildcard demonstrates allowing all origins
func Example_corsWildcard() {
	engine := we.New()

	// Configure CORS to allow any origin
	corsFilter := filters.Cors().
		AllowedOrigins("*").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured for all origins")
	// Output: CORS filter configured for all origins
}

// Example_corsWithCredentials demonstrates enabling credentials support
func Example_corsWithCredentials() {
	engine := we.New()

	// Configure CORS with credentials support
	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").
		AllowedHeaders("Content-Type", "Authorization").
		AllowCredentials().
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured with credentials")
	// Output: CORS filter configured with credentials
}

// Example_corsPathSpecific demonstrates path-specific CORS configuration
func Example_corsPathSpecific() {
	engine := we.New()

	// Configure different CORS rules for different paths
	corsFilter := filters.Cors().
		// Default restrictive configuration
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").

		// Public API - allow all origins
		Path("/api/public/*").
		AllowedOrigins("*").
		AllowedMethods("GET").
		Add().

		// Admin API - very restrictive
		Path("/api/admin/**").
		AllowedOrigins("https://admin.example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowCredentials().
		Add().
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured with path-specific rules")
	// Output: CORS filter configured with path-specific rules
}

// Example_corsAdvanced demonstrates advanced CORS configuration
func Example_corsAdvanced() {
	engine := we.New()

	// Configure CORS with all options
	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com", "https://app.example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE", "PATCH").
		AllowedHeaders("Content-Type", "Authorization", "X-Custom-Header").
		ExposedHeaders("X-Request-ID", "X-RateLimit-Remaining").
		AllowCredentials().
		MaxAge(7200). // 2 hours
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured with advanced options")
	// Output: CORS filter configured with advanced options
}

// Example_corsMultiplePaths demonstrates configuring multiple paths with the same rules
func Example_corsMultiplePaths() {
	engine := we.New()

	// Configure same CORS rules for multiple API versions
	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com").

		// Apply same rules to v1 and v2 API paths
		Path("/api/v1/*", "/api/v2/*").
		AllowedOrigins("*").
		AllowedMethods("GET", "POST").
		Add().
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured for multiple paths")
	// Output: CORS filter configured for multiple paths
}

// Example_corsPublicAPI demonstrates a typical public API configuration
func Example_corsPublicAPI() {
	engine := we.New()

	// Configure CORS for a public API
	corsFilter := filters.Cors().
		Path("/*").
		AllowedOrigins("*").
		AllowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS").
		AllowedHeaders("Content-Type", "Authorization", "X-Api-Key").
		ExposedHeaders("X-RateLimit-Remaining", "X-RateLimit-Reset").
		MaxAge(3600).
		Add().
		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured for public API")
	// Output: CORS filter configured for public API
}

// Example_corsDisabled demonstrates disabling CORS for specific paths
func Example_corsDisabled() {
	engine := we.New()

	// Configure CORS with default for all paths, but disable for internal endpoints
	corsFilter := filters.Cors().
		// Default: enable CORS
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").

		// Disable CORS for internal paths
		Path("/internal/*", "/health", "/metrics").
		Disabled().
		Add().

		Build()

	engine.AddFilter(corsFilter)

	fmt.Println("CORS filter configured with disabled paths")
	// Output: CORS filter configured with disabled paths
}
