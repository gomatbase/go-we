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

	engine.AddFilter(corsFilter)

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

	engine.AddFilter(corsFilter)

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
*/
package filters
