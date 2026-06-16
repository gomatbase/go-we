// Copyright 2026 GOM. All rights reserved.
// Since 01/04/2026 By GOM
// Licensed under MIT License

/*
Package filters provides common HTTP filters for the go-we web framework.

# Overview

This package contains reusable filter implementations for common web application
needs such as CORS handling, security headers, and request debug logging.

Filters in this package follow the standard we.Filter interface and can be added
to any go-we engine using the AddFilter method.

# CORS Filter

The CORS (Cross-Origin Resource Sharing) filter enables controlled access to
resources from different origins. It supports both global and path-specific
configuration with wildcard path matching.

# Basic Usage

The simplest CORS configuration allows specific origins with default settings:

	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com", "https://app.example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowedHeaders("Content-Type", "Authorization").
		AllowCredentials().
		Build()

	engine := we.New().Filter(corsFilter).Build()

# Path-Specific Configuration

For more complex scenarios, you can configure different CORS rules for different
paths using wildcard matching:

	corsFilter := filters.Cors().
		// Default configuration (applies to all paths unless overridden)
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

	engine := we.New().Filter(corsFilter).Build()

# Wildcard Path Patterns

The CORS filter supports wildcard patterns for path matching:

  - Exact paths: "/api/health" - Only matches the exact path
  - Single wildcard: "/api/*" - Matches /api/users, /api/posts (single level)
  - Double wildcard: "/api/**" - Matches /api/users/123/profile (multiple levels)

Path-specific configurations take precedence over default configuration,
with more specific paths taking precedence over less specific ones.

# Disabling CORS for Specific Paths

You can explicitly disable CORS for specific paths even when a default
configuration is set. This is useful for internal endpoints, health checks,
or other paths that should not have CORS headers:

	corsFilter := filters.Cors().
		// Default: enable CORS for all paths
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").

		// Disable CORS for internal endpoints
		Path("/internal/*", "/health").
			Disabled().
			Add().

		Build()

When CORS is disabled for a path, no CORS headers will be added and preflight
requests will not be handled specially.

# Preflight Requests

The CORS filter automatically handles OPTIONS preflight requests by returning
appropriate CORS headers along with a 204 No Content status. This allows
browsers to determine whether the actual request is safe to send.

# Security Considerations

When using CORS filters, keep these security best practices in mind:

  - Avoid wildcard origins ("*") in production unless absolutely necessary
  - Never combine AllowCredentials() with wildcard origins (this will cause a panic)
  - Be specific with AllowedHeaders to minimize attack surface
  - Use path-specific configs to apply the principle of least privilege
  - Consider using separate configurations for public vs. authenticated endpoints

# Examples

Allow all origins for a public API:

	corsFilter := filters.Cors().
		Path("/*").
			AllowedOrigins("*").
			AllowedMethods("GET", "POST", "PUT", "DELETE").
			Add().
		Build()

Restrict to specific origins with credentials:

	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").
		AllowedHeaders("Content-Type", "Authorization", "X-Custom-Header").
		ExposedHeaders("X-Request-ID", "X-RateLimit-Remaining").
		AllowCredentials().
		MaxAge(7200).
		Build()

See the package examples for more detailed usage scenarios.

# ResponseHeaders Filter

The ResponseHeaders filter provides a secure and flexible way to add HTTP response
headers to your application. It includes secure defaults for common security headers
and allows full customization for any header.

# Secure Defaults

By default, the filter automatically applies two essential security headers:

  - X-Content-Type-Options: nosniff (prevents MIME-type sniffing)
  - X-Frame-Options: SAMEORIGIN (prevents clickjacking)

These defaults are applied automatically when you build the filter without explicitly
configuring them, providing a secure baseline for your application.

# Basic Usage

The simplest configuration relies on secure defaults:

	filter := filters.ResponseHeaders().Build()
	engine := we.New().Filter(filter).Build()

This automatically adds the two default security headers to all responses.

# Security Headers

The filter provides convenient methods for common security headers:

	filter := filters.ResponseHeaders().
		// Explicitly set NoSniff (enabled by default)
		NoSniff().
		// Set frame options (default is SAMEORIGIN)
		FrameOptions(filters.FrameOptionDeny).
		// Add HTTP Strict Transport Security
		HSTS(31536000, true, false).  // maxAge, includeSubDomains, preload
		// Set Content Security Policy
		CSP("default-src 'self'; script-src 'self' 'unsafe-inline'").
		// Set Referrer Policy
		ReferrerPolicy(ReferrerPolicyStrictOriginWhenCrossOrigin).
		// Set Permissions Policy
		PermissionsPolicy("geolocation=(), camera=()").
		// Cross-Origin Embedder Policy
		COEP(COEPRequireCorp).
		// Cross-Origin Opener Policy
		COOP(COOPSameOrigin).
		// Cross-Origin Resource Policy
		CORP(CORPSameSite).
		Build()

	engine := we.New().Filter(filter).Build()

# HSTS Special Handling

The HSTS (HTTP Strict Transport Security) header is only sent over HTTPS connections.
If a request comes in over HTTP (request.TLS is nil), the HSTS header is silently
skipped. This prevents potential security issues from sending HSTS over insecure
connections.

	filter := filters.ResponseHeaders().
		HSTS(31536000, true, true).  // Only sent on HTTPS
		Build()

# Frame Options

The X-Frame-Options header has a custom type with constants for type-safe usage:

	// Deny all framing
	FrameOptions(filters.FrameOptionDeny)

	// Allow same-origin framing (default)
	FrameOptions(filters.FrameOptionSameOrigin)

	// Allow specific origin
	FrameOptions(filters.FrameOptionAllowFrom("https://trusted.example.com"))

# Type-Safe Security Headers

Several security headers use custom string types with predefined constants for type safety:

Referrer-Policy constants:

	ReferrerPolicyNoReferrer                      // "no-referrer"
	ReferrerPolicyNoReferrerWhenDowngrade        // "no-referrer-when-downgrade"
	ReferrerPolicyOrigin                          // "origin"
	ReferrerPolicyOriginWhenCrossOrigin          // "origin-when-cross-origin"
	ReferrerPolicySameOrigin                      // "same-origin"
	ReferrerPolicyStrictOrigin                    // "strict-origin"
	ReferrerPolicyStrictOriginWhenCrossOrigin    // "strict-origin-when-cross-origin"
	ReferrerPolicyUnsafeURL                       // "unsafe-url"

Cross-Origin-Embedder-Policy constants:

	COEPUnsafeNone          // "unsafe-none"
	COEPRequireCorp         // "require-corp"
	COEPCredentialless      // "credentialless"

Cross-Origin-Opener-Policy constants:

	COOPUnsafeNone                // "unsafe-none"
	COOPSameOriginAllowPopups     // "same-origin-allow-popups"
	COOPSameOrigin                // "same-origin"

Cross-Origin-Resource-Policy constants:

	CORPSameSite        // "same-site"
	CORPSameOrigin      // "same-origin"
	CORPCrossOrigin     // "cross-origin"

Example usage:

	filter := filters.ResponseHeaders().
		ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin).
		COEP(filters.COEPRequireCorp).
		COOP(filters.COOPSameOrigin).
		CORP(filters.CORPSameOrigin).
		Build()

# Custom Headers

You can add any custom header using the Header() method:

	filter := filters.ResponseHeaders().
		Header("X-API-Version", "v1.0").
		Header("X-Request-ID", "generated-id").
		Header("Cache-Control", "no-store, no-cache, must-revalidate").
		Build()

Headers are applied in the order they are defined. If you set the same header
multiple times, the last value wins.

# Disabling Default Headers

You can explicitly disable the default security headers if needed:

	filter := filters.ResponseHeaders().
		DisableNoSniff().          // Remove X-Content-Type-Options
		DisableFrameOptions().     // Remove X-Frame-Options
		CSP("default-src 'self'"). // But add CSP
		Build()

# Path-Specific Configuration

Like the CORS filter, ResponseHeaders supports path-specific configurations with
wildcard matching:

	filter := filters.ResponseHeaders().
		// Default: secure headers for all paths
		HSTS(31536000, true, false).

		// API paths: add custom headers but keep defaults
		Path("/api/**").
			Header("X-API-Version", "v2.0").
			Header("Cache-Control", "no-store").
			Add().

		// Public assets: different frame options
		Path("/assets/**").
			FrameOptions(filters.FrameOptionDeny).
			Header("Cache-Control", "public, max-age=31536000").
			Add().

		// Admin area: strictest security
		Path("/admin/**").
			FrameOptions(filters.FrameOptionDeny).
			HSTS(63072000, true, true).
			CSP("default-src 'self'").
			Add().

		Build()

	engine := we.New().Filter(filter).Build()

# Disabling Headers for Specific Paths

You can disable all headers for specific paths (useful for health checks,
internal endpoints, or API endpoints that should not have these headers):

	filter := filters.ResponseHeaders().
		// Default: add security headers everywhere
		HSTS(31536000, true, false).

		// No headers for these paths
		Path("/health", "/metrics", "/internal/*").
			Disabled().
			Add().

		Build()

# Path Precedence

When multiple path configurations could match a request, the most specific path wins:

  - Exact paths (e.g., "/api/users") are most specific
  - Single wildcards (e.g., "/api/*") are less specific
  - Double wildcards (e.g., "/api/**") are least specific
  - Default configuration (/** and /) applies when no specific path matches

# Security Best Practices

When using the ResponseHeaders filter, consider these recommendations:

  - Start with the secure defaults and only disable them if you have a specific reason
  - Always use HSTS with long max-age (at least 1 year = 31536000 seconds) for production
  - Implement a strict Content-Security-Policy to prevent XSS attacks
  - Use FrameOptionDeny for paths that should never be embedded
  - Set appropriate Referrer-Policy to control what information is sent in referrers
  - For APIs, consider disabling frame-related headers if they're not relevant
  - Test headers in development before deploying to production
  - Use path-specific configurations to apply different policies to different areas

# Common Patterns

API endpoints with caching disabled:

	filter := filters.ResponseHeaders().
		Path("/api/**").
			Header("Cache-Control", "no-store, no-cache, must-revalidate").
			Header("Pragma", "no-cache").
			Add().
		Build()

Maximum security for authenticated areas:

	filter := filters.ResponseHeaders().
		Path("/app/**", "/admin/**").
			FrameOptions(filters.FrameOptionDeny).
			HSTS(63072000, true, true).
			CSP("default-src 'self'; script-src 'self'; object-src 'none'").
			ReferrerPolicy(ReferrerPolicyNoReferrer).
			COEP(COEPRequireCorp).
			COOP(COOPSameOrigin).
			CORP(CORPSameOrigin).
			Add().
		Build()

Public content with relaxed headers:

	filter := filters.ResponseHeaders().
		Path("/public/**").
			DisableFrameOptions().  // Allow embedding
			Header("Cache-Control", "public, max-age=86400").
			Add().
		Build()

See the package examples for more detailed usage scenarios.
*/
package filters
