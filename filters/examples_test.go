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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

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

	engine.Filter(corsFilter)

	fmt.Println("CORS filter configured with disabled paths")
	// Output: CORS filter configured with disabled paths
}

// Example_responseHeadersBasic demonstrates basic usage with secure defaults
func Example_responseHeadersBasic() {
	engine := we.New()

	// Configure with secure defaults (NoSniff + FrameOptions SAMEORIGIN)
	filter := filters.ResponseHeaders().Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with secure defaults")
	// Output: ResponseHeaders filter configured with secure defaults
}

// Example_responseHeadersSecurity demonstrates common security headers
func Example_responseHeadersSecurity() {
	engine := we.New()

	// Configure comprehensive security headers
	filter := filters.ResponseHeaders().
		FrameOptions(filters.FrameOptionDeny).
		HSTS(31536000, true, false). // 1 year, includeSubDomains, no preload
		CSP("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'").
		ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin).
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with security headers")
	// Output: ResponseHeaders filter configured with security headers
}

// Example_responseHeadersHSTS demonstrates HSTS configuration
func Example_responseHeadersHSTS() {
	engine := we.New()

	// Configure HSTS with various options
	filter := filters.ResponseHeaders().
		// HSTS for 2 years with includeSubDomains and preload
		HSTS(63072000, true, true).
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with HSTS")
	// Output: ResponseHeaders filter configured with HSTS
}

// Example_responseHeadersCustom demonstrates custom headers
func Example_responseHeadersCustom() {
	engine := we.New()

	// Add custom headers along with defaults
	filter := filters.ResponseHeaders().
		Header("X-API-Version", "v2.0").
		Header("X-Request-ID", "generated-id").
		Header("Cache-Control", "no-store, no-cache, must-revalidate").
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with custom headers")
	// Output: ResponseHeaders filter configured with custom headers
}

// Example_responseHeadersCSP demonstrates Content-Security-Policy configuration
func Example_responseHeadersCSP() {
	engine := we.New()

	// Configure a strict Content Security Policy
	filter := filters.ResponseHeaders().
		CSP("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'").
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with CSP")
	// Output: ResponseHeaders filter configured with CSP
}

// Example_responseHeadersPathSpecific demonstrates path-specific configuration
func Example_responseHeadersPathSpecific() {
	engine := we.New()

	// Configure different headers for different paths
	filter := filters.ResponseHeaders().
		// Default: secure headers for all paths
		HSTS(31536000, true, false).

		// API paths: add custom headers
		Path("/api/**").
		Header("X-API-Version", "v2.0").
		Header("Cache-Control", "no-store").
		Add().

		// Public assets: longer cache, allow framing from same origin
		Path("/assets/**").
		Header("Cache-Control", "public, max-age=31536000").
		Add().
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with path-specific rules")
	// Output: ResponseHeaders filter configured with path-specific rules
}

// Example_responseHeadersDisableDefaults demonstrates disabling default headers
func Example_responseHeadersDisableDefaults() {
	engine := we.New()

	// Disable default security headers for specific needs
	filter := filters.ResponseHeaders().
		DisableNoSniff().
		DisableFrameOptions().
		// But add custom security headers
		CSP("default-src 'self'").
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with disabled defaults")
	// Output: ResponseHeaders filter configured with disabled defaults
}

// Example_responseHeadersDisabledPaths demonstrates disabling headers for specific paths
func Example_responseHeadersDisabledPaths() {
	engine := we.New()

	// Configure headers with exceptions for specific paths
	filter := filters.ResponseHeaders().
		// Default: add security headers everywhere
		HSTS(31536000, true, false).

		// No headers for these paths
		Path("/health", "/metrics", "/internal/*").
		Disabled().
		Add().
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with disabled paths")
	// Output: ResponseHeaders filter configured with disabled paths
}

// Example_responseHeadersAPI demonstrates a typical API configuration
func Example_responseHeadersAPI() {
	engine := we.New()

	// Configure headers suitable for an API
	filter := filters.ResponseHeaders().
		Path("/api/**").
		// Prevent caching of API responses
		Header("Cache-Control", "no-store, no-cache, must-revalidate").
		Header("Pragma", "no-cache").
		Header("X-API-Version", "v1.0").
		// Keep security defaults
		NoSniff().
		Add().
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured for API")
	// Output: ResponseHeaders filter configured for API
}

// Example_responseHeadersMaxSecurity demonstrates maximum security configuration
func Example_responseHeadersMaxSecurity() {
	engine := we.New()

	// Configure maximum security for authenticated areas
	filter := filters.ResponseHeaders().
		Path("/app/**", "/admin/**").
		FrameOptions(filters.FrameOptionDeny).
		HSTS(63072000, true, true). // 2 years with preload
		CSP("default-src 'self'; script-src 'self'; object-src 'none'").
		ReferrerPolicy(filters.ReferrerPolicyNoReferrer).
		PermissionsPolicy("geolocation=(), camera=(), microphone=()").
		COEP(filters.COEPRequireCorp).
		COOP(filters.COOPSameOrigin).
		CORP(filters.CORPSameOrigin).
		Add().
		Build()

	engine.Filter(filter)

	fmt.Println("ResponseHeaders filter configured with maximum security")
	// Output: ResponseHeaders filter configured with maximum security
}
