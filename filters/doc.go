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

# BodySizeLimit Filter

The BodySizeLimit filter enforces maximum request body sizes to prevent DoS attacks
and resource exhaustion from oversized uploads or requests.

# Basic Usage

The simplest configuration uses the default maximum size of 10MB:

	filter := filters.DefaultBodySizeLimit().Build()

	engine := we.New().Filter(filter).Build()

# Custom Maximum Size

Set a custom maximum body size for all requests:

	filter := filters.DefaultBodySizeLimit().
		MaxSize(5 * 1024 * 1024).  // 5MB
		Build()

# Path-Specific Limits

Configure different size limits for different paths:

	filter := filters.DefaultBodySizeLimit().
		MaxSize(1024 * 1024).  // 1MB default
		Path("/api/upload").
			MaxSize(100 * 1024 * 1024).  // 100MB for uploads
		Path("/api/import").
			MaxSize(50 * 1024 * 1024).   // 50MB for imports
		Build()

	engine := we.New().Filter(filter).Build()

# How It Works

The filter performs two checks:

 1. **Content-Length Header Check**: If the Content-Length header indicates the body
    exceeds the limit, the request is immediately rejected with HTTP 413 (Entity Too Large).

 2. **Body Reader Wrapping**: The request body reader is wrapped with http.MaxBytesReader
    to prevent reading beyond the limit, protecting against missing or incorrect
    Content-Length headers.

If either check fails, a RequestEntityTooLargeError event is returned.

# Size Constants

Common size limits in bytes:

	1 KB   = 1024
	1 MB   = 1024 * 1024         (1048576)
	5 MB   = 5 * 1024 * 1024     (5242880)
	10 MB  = 10 * 1024 * 1024    (10485760) - default
	50 MB  = 50 * 1024 * 1024    (52428800)
	100 MB = 100 * 1024 * 1024   (104857600)

# Examples

Basic protection against large uploads:

	filter := filters.DefaultBodySizeLimit().
		MaxSize(10 * 1024 * 1024).  // 10MB max
		Build()

Different limits for different endpoints:

	filter := filters.DefaultBodySizeLimit().
		MaxSize(1024 * 100).  // 100KB default for JSON APIs
		Path("/api/upload", "/api/media/**").
			MaxSize(500 * 1024 * 1024).  // 500MB for file uploads
		Path("/api/import").
			MaxSize(100 * 1024 * 1024).  // 100MB for data imports
		Build()

Combine with other filters:

	corsFilter := filters.Cors().AllowedOrigins("https://example.com").Build()
	sizeFilter := filters.DefaultBodySizeLimit().MaxSize(5 * 1024 * 1024).Build()

	engine := we.New().
		Filter(corsFilter).
		Filter(sizeFilter).
		Build()

# Security Considerations

- Set reasonable limits based on your application's legitimate use cases
- Smaller limits prevent potential DoS attacks through large payloads
- Consider that different endpoints may have different requirements (file uploads vs. JSON APIs)
- Test with your actual client behavior to ensure limits don't break legitimate functionality
- Monitor rejection logs to detect potential attack patterns

See the package examples for more detailed usage scenarios.

# CSRF Filter

The CSRF (Cross-Site Request Forgery) filter protects your application against CSRF attacks
using the synchronizer token pattern. Tokens are generated, validated, and stored in user sessions.

# Basic Usage

The simplest configuration uses default settings with no exempt paths:

	filter := filters.Csrf().Build()

	engine := we.New().Filter(filter).Build()

# Exempting Paths

Exempt paths (typically API endpoints with Bearer authentication) from CSRF validation:

	filter := filters.Csrf().
		ExemptPaths("/api/webhook", "/api/external").
		Build()

	engine := we.New().Filter(filter).Build()

# Custom Configuration

Customize header names, field names, and token length:

	filter := filters.Csrf().
		HeaderName("X-Custom-CSRF").          // Default: X-CSRF-Token
		FieldName("csrf_token").              // Default: _csrf
		TokenLength(64).                      // Default: 32 bytes
		ExemptPaths("/api/health").
		Build()

# How It Works

 1. **Token Generation**: For safe HTTP methods (GET, HEAD, OPTIONS), the filter generates
    a random token and stores it in the session if one doesn't already exist.

 2. **Token Validation**: For state-changing methods (POST, PUT, DELETE, PATCH), the filter
    validates that the request includes a valid CSRF token. Tokens can be provided via:
    - HTTP header (default: X-CSRF-Token)
    - Form field (default: _csrf)

3. **Exemption**: Paths in the exempt list bypass CSRF validation entirely.

# Safe Methods

The filter considers these methods safe and does not require CSRF tokens:
- GET
- HEAD
- OPTIONS

# State-Changing Methods

These methods require a valid CSRF token:
- POST
- PUT
- DELETE
- PATCH

# Integration with Session Management

CSRF tokens are stored in the session using the key "_csrf_token". When a user logs out
or the session is cleared, the token is automatically removed.

	session := scope.Session()
	token := session.Get("_csrf_token")  // Retrieve token for HTML form

# Token Rotation

To force a new token (e.g., after login for security), clear the session token:

	session := scope.Session()
	session.Delete("_csrf_token")
	// Next request will generate a new token

# Examples

Typical configuration for a web application:

	filter := filters.Csrf().
		ExemptPaths("/api/public/**", "/health", "/metrics").
		Build()

	engine := we.New().
		Filter(filter).
		Build()

Using custom header names for JavaScript frameworks:

	filter := filters.Csrf().
		HeaderName("X-XSRF-TOKEN").         // Angular style
		FieldName("xsrf-token").
		Build()

Combining with other security filters:

	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com").
		Build()

	csrfFilter := filters.Csrf().
		ExemptPaths("/api/**").  // APIs use Bearer tokens
		Build()

	engine := we.New().
		Filter(corsFilter).
		Filter(csrfFilter).
		Build()

# Security Considerations

- Always include CSRF tokens in all state-changing requests
- Ensure session management is properly configured and secure
- Use HTTPS in production to prevent token interception
- Regenerate tokens after sensitive operations (login, privilege escalation)
- Do not exempt paths unless they use alternative authentication (e.g., Bearer tokens)
- Monitor failed token validation attempts as they may indicate attacks

# HTML Form Integration

To use CSRF protection in HTML forms, retrieve the token from the session and include it:

	// In your template/handler:
	token := scope.Session().Get("_csrf_token")

	// In HTML form:
	<form method="POST" action="/api/resource">
		<input type="hidden" name="_csrf" value="{{ .Token }}">
		<!-- other fields -->
	</form>

See the package examples for more detailed usage scenarios.

# RateLimiter Filter

The RateLimiter filter prevents abuse and protects against DoS attacks by limiting the number
of requests a client can make within a specified time window using the token bucket algorithm.

# Basic Usage

The simplest configuration uses default rate limiting (100 requests per second, burst of 20):

	filter := filters.RateLimiter().Build()

	engine := we.New().Filter(filter).Build()

# Custom Rate Limits

Configure custom requests per second and burst size:

	filter := filters.RateLimiter().
		RequestsPerSecond(50).
		Burst(10).
		Build()

# Exempt Paths

Exempt specific paths (e.g., health checks, metrics) from rate limiting:

	filter := filters.RateLimiter().
		RequestsPerSecond(100).
		Burst(20).
		ExemptPaths("/health", "/metrics", "/ready").
		Build()

# Custom Identifiers

By default, rate limits are applied per client IP address. You can customize the identifier
to use user ID, API key, or any other criteria:

	filter := filters.RateLimiter().
		RequestsPerSecond(100).
		Burst(20).
		Identifier(func(scope we.RequestScope) string {
			// Use user ID from session if authenticated, fall back to IP
			user := scope.Session().Get("user_id")
			if user != nil {
				return "user:" + user.(string)
			}
			// Fall back to IP address
			request := scope.Request()
			if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
				return "ip:" + xff
			}
			return "ip:" + request.RemoteAddr
		}).
		Build()
		}).
		Build()

# How It Works

The filter uses the **token bucket algorithm** to implement rate limiting:

1. Each unique identifier (client IP by default) gets its own token bucket
2. Tokens are added to the bucket at a rate of RequestsPerSecond per second
3. The bucket can hold a maximum of Burst tokens
4. Each request consumes one token; if no tokens are available, the request is rejected
5. Stale buckets (unused for 10 minutes) are automatically cleaned up

# IP Address Detection

The filter automatically handles proxied requests:

1. X-Forwarded-For header (for load balancers/proxies)
2. X-Real-IP header (for nginx/other proxies)
3. Direct remote address as fallback

This ensures accurate rate limiting even behind reverse proxies.

# Examples

Protect API endpoints with different limits:

	filter := filters.RateLimiter().
		RequestsPerSecond(100).
		Burst(20).
		ExemptPaths("/health", "/metrics").
		Build()

	engine := we.New().Filter(filter).Build()

Strict rate limiting for public endpoints:

	filter := filters.RateLimiter().
		RequestsPerSecond(10).
		Burst(5).
		ExemptPaths("/health", "/status").
		Build()

Per-user rate limiting:

	filter := filters.RateLimiter().
		RequestsPerSecond(100).  // Default for anonymous
		Identifier(func(scope we.RequestScope) string {
			// Different limits per user
			user := scope.Session().Get("user_id")
			if user != nil {
				return "user:" + user.(string)
			}
			return "anonymous:" + scope.Request().RemoteAddr
		}).
		Build()

Combine with other filters:

	csrfFilter := filters.Csrf().ExemptPaths("/api").Build()
	rateLimitFilter := filters.RateLimiter().
		RequestsPerSecond(100).
		ExemptPaths("/health").
		Build()

	engine := we.New().
		Filter(csrfFilter).
		Filter(rateLimitFilter).
		Build()

# Default Limits

The default configuration is suitable for most web applications:
- Requests per second: 100
- Burst size: 20
- Identifier: Client IP address

These can be easily customized for your specific needs.

# HTTP Status Codes

- **429 Too Many Requests**: When the rate limit is exceeded, clients receive this status code

# Security Considerations

- Rate limiting should be combined with other security measures (CORS, CSRF, etc.)
- Behind a reverse proxy, ensure X-Forwarded-For or X-Real-IP headers are properly set
- Exempt paths (like health checks) should be carefully chosen to avoid bypass opportunities
- Monitor rate limit rejections to detect attack patterns
- Adjust RequestsPerSecond and Burst based on your expected traffic patterns
- Consider per-user limits for authenticated endpoints

# Production Recommendations

For production deployments:
- Use per-user identifiers for authenticated endpoints
- Implement stricter limits for public/unauthenticated endpoints
- Monitor the rate limiting statistics
- Adjust limits based on actual usage patterns and attack observations
- Use load balancer rate limiting in combination with application-level limits

See the package examples for more detailed usage scenarios.
*/
package filters
