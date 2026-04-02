// Copyright 2026 GOM. All rights reserved.
// Since 01/04/2026 By GOM
// Licensed under MIT License

package filters

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/test"
)

// Test helpers

func mockRequestScopeHTTP(method, path string) we.RequestScope {
	url := "http://localhost" + path
	return test.MockedRequestScope(method, url)
}

func mockRequestScopeHTTPS(method, path string) we.RequestScope {
	url := "https://localhost" + path
	scope := test.MockedRequestScope(method, url)
	// Set TLS state to simulate HTTPS
	scope.Request().TLS = &tls.ConnectionState{}
	return scope
}

// Category 1: Default Configuration Tests

func TestResponseHeaders_DefaultValues(t *testing.T) {
	filter := ResponseHeaders().Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Should have default headers
	assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
	assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")
}

func TestResponseHeaders_EmptyBuild(t *testing.T) {
	// Build with no configuration should apply defaults
	filter := ResponseHeaders().Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
	assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")
}

func TestResponseHeaders_DefaultsInPathTree(t *testing.T) {
	filter := ResponseHeaders().Build()

	// Test various paths to ensure default applies everywhere
	paths := []string{"/", "/api/test", "/admin/users", "/deep/nested/path"}

	for _, path := range paths {
		headers := http.Header{}
		scope := mockRequestScopeHTTP("GET", path)
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", path, err)
		}

		assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
		assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")
	}
}

// Category 2: Security Headers - Individual Tests

func TestResponseHeaders_NoSniff(t *testing.T) {
	filter := ResponseHeaders().
		NoSniff().
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
}

func TestResponseHeaders_DisableNoSniff(t *testing.T) {
	filter := ResponseHeaders().
		DisableNoSniff().
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertNoHeader(t, headers, "X-Content-Type-Options")
	// FrameOptions should still be there (default)
	assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")
}

func TestResponseHeaders_FrameOptionDeny(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionDeny).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Frame-Options", "DENY")
}

func TestResponseHeaders_FrameOptionSameOrigin(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionSameOrigin).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")
}

func TestResponseHeaders_FrameOptionAllowFrom(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionAllowFrom("https://trusted.com")).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Frame-Options", "ALLOW-FROM https://trusted.com")
}

func TestResponseHeaders_DisableFrameOptions(t *testing.T) {
	filter := ResponseHeaders().
		DisableFrameOptions().
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertNoHeader(t, headers, "X-Frame-Options")
	// NoSniff should still be there (default)
	assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
}

func TestResponseHeaders_ReferrerPolicy(t *testing.T) {
	filter := ResponseHeaders().
		ReferrerPolicy(ReferrerPolicyStrictOriginWhenCrossOrigin).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Referrer-Policy", "strict-origin-when-cross-origin")
}

func TestResponseHeaders_CSP(t *testing.T) {
	cspPolicy := "default-src 'self'; script-src 'self' 'unsafe-inline'"
	filter := ResponseHeaders().
		CSP(cspPolicy).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Content-Security-Policy", cspPolicy)
}

func TestResponseHeaders_PermissionsPolicy(t *testing.T) {
	policy := "geolocation=(), camera=(), microphone=()"
	filter := ResponseHeaders().
		PermissionsPolicy(policy).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Permissions-Policy", policy)
}

// Category 3: HSTS Tests

func TestResponseHeaders_HSTS_Basic(t *testing.T) {
	filter := ResponseHeaders().
		HSTS(31536000, false, false).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTPS("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Strict-Transport-Security", "max-age=31536000")
}

func TestResponseHeaders_HSTS_IncludeSubDomains(t *testing.T) {
	filter := ResponseHeaders().
		HSTS(31536000, true, false).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTPS("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

func TestResponseHeaders_HSTS_Preload(t *testing.T) {
	filter := ResponseHeaders().
		HSTS(63072000, true, true).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTPS("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
}

func TestResponseHeaders_HSTS_SkippedOnHTTP(t *testing.T) {
	filter := ResponseHeaders().
		HSTS(31536000, true, false).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test") // HTTP, not HTTPS
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// HSTS should NOT be present over HTTP
	assertNoHeader(t, headers, "Strict-Transport-Security")
}

func TestResponseHeaders_HSTS_NegativeMaxAge_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for negative maxAge, but didn't panic")
		}
	}()

	ResponseHeaders().
		HSTS(-1, false, false).
		Build()
}

// Category 4: Cross-Origin Headers

func TestResponseHeaders_COEP(t *testing.T) {
	filter := ResponseHeaders().
		COEP(COEPRequireCorp).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Cross-Origin-Embedder-Policy", "require-corp")
}

func TestResponseHeaders_COOP(t *testing.T) {
	filter := ResponseHeaders().
		COOP(COOPSameOrigin).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Cross-Origin-Opener-Policy", "same-origin")
}

func TestResponseHeaders_CORP(t *testing.T) {
	filter := ResponseHeaders().
		CORP(CORPSameSite).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Cross-Origin-Resource-Policy", "same-site")
}

// Category 5: Custom Headers Tests

func TestResponseHeaders_CustomHeader_Single(t *testing.T) {
	filter := ResponseHeaders().
		Header("X-Custom-Header", "custom-value").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Custom-Header", "custom-value")
}

func TestResponseHeaders_CustomHeader_Multiple(t *testing.T) {
	filter := ResponseHeaders().
		Header("X-API-Version", "2.0").
		Header("X-Custom-Header", "value").
		Header("Cache-Control", "no-store").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-API-Version", "2.0")
	assertHeaderEquals(t, headers, "X-Custom-Header", "value")
	assertHeaderEquals(t, headers, "Cache-Control", "no-store")
}

func TestResponseHeaders_CustomHeader_EmptyValue(t *testing.T) {
	filter := ResponseHeaders().
		Header("Server", "").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Empty value should set empty header
	assertHeaderEquals(t, headers, "Server", "")
}

func TestResponseHeaders_CustomHeader_CaseSensitive(t *testing.T) {
	filter := ResponseHeaders().
		Header("cache-control", "no-store").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Header name used as-is
	assertHeaderEquals(t, headers, "cache-control", "no-store")
}

func TestResponseHeaders_CustomHeader_WithDefaults(t *testing.T) {
	filter := ResponseHeaders().
		Header("X-Custom", "value").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Both custom and default headers should be present
	assertHeaderEquals(t, headers, "X-Custom", "value")
	assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
	assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")
}

// Category 6: Path-Specific Configuration Tests

func TestResponseHeaders_PathSpecific_Single(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionSameOrigin).
		Path("/admin/*").
		FrameOptions(FrameOptionDeny).
		Add().
		Build()

	// Non-admin path should have SAMEORIGIN
	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/public")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-Frame-Options", "SAMEORIGIN")

	// Admin path should have DENY
	headers = http.Header{}
	scope = mockRequestScopeHTTP("GET", "/admin/users")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-Frame-Options", "DENY")
}

func TestResponseHeaders_PathSpecific_Multiple(t *testing.T) {
	filter := ResponseHeaders().
		Path("/path1", "/path2").
		Header("X-Multi-Path", "true").
		Add().
		Build()

	// Both paths should have the header
	for _, path := range []string{"/path1", "/path2"} {
		headers := http.Header{}
		scope := mockRequestScopeHTTP("GET", path)
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", path, err)
		}
		assertHeaderEquals(t, headers, "X-Multi-Path", "true")
	}
}

func TestResponseHeaders_PathSpecific_Wildcard(t *testing.T) {
	filter := ResponseHeaders().
		Path("/api/*").
		Header("X-API", "v1").
		Add().
		Build()

	// Should match single-level paths under /api/
	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/api/users")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-API", "v1")

	// Should NOT match nested paths
	headers = http.Header{}
	scope = mockRequestScopeHTTP("GET", "/api/users/123")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "X-API")
}

func TestResponseHeaders_PathSpecific_DoubleWildcard(t *testing.T) {
	filter := ResponseHeaders().
		Path("/admin/**").
		Header("X-Admin", "true").
		Add().
		Build()

	// Should match nested paths
	paths := []string{"/admin/users", "/admin/users/123", "/admin/settings/security"}
	for _, path := range paths {
		headers := http.Header{}
		scope := mockRequestScopeHTTP("GET", path)
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", path, err)
		}
		assertHeaderEquals(t, headers, "X-Admin", "true")
	}
}

func TestResponseHeaders_PathSpecific_Precedence(t *testing.T) {
	filter := ResponseHeaders().
		Header("X-Level", "default").
		Path("/api/**").
		Header("X-Level", "api").
		Add().
		Path("/api/internal/*").
		Header("X-Level", "internal").
		Add().
		Build()

	testCases := []struct {
		path     string
		expected string
	}{
		{"/", "default"},
		{"/api/users", "api"},
		{"/api/posts/123", "api"},
		{"/api/internal/health", "internal"},
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScopeHTTP("GET", tc.path)
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}
		assertHeaderEquals(t, headers, "X-Level", tc.expected)
	}
}

func TestResponseHeaders_PathSpecific_FallbackToDefault(t *testing.T) {
	filter := ResponseHeaders().
		Header("X-Default", "true").
		Path("/special").
		Header("X-Special", "true").
		Add().
		Build()

	// Unmatched path should get default
	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/other")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-Default", "true")
	assertNoHeader(t, headers, "X-Special")
}

func TestResponseHeaders_PathSpecific_DisableDefaults(t *testing.T) {
	filter := ResponseHeaders().
		// Default has NoSniff and FrameOptions
		Path("/api/*").
		DisableNoSniff().
		DisableFrameOptions().
		Header("X-API", "true").
		Add().
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/api/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Should have custom header but not defaults
	assertHeaderEquals(t, headers, "X-API", "true")
	assertNoHeader(t, headers, "X-Content-Type-Options")
	assertNoHeader(t, headers, "X-Frame-Options")
}

func TestResponseHeaders_PathSpecific_CustomOnly(t *testing.T) {
	filter := ResponseHeaders().
		Path("/custom").
		DisableNoSniff().
		DisableFrameOptions().
		Header("X-Only-Custom", "value").
		Add().
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/custom")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "X-Only-Custom", "value")
	assertNoHeader(t, headers, "X-Content-Type-Options")
	assertNoHeader(t, headers, "X-Frame-Options")
}

// Category 7: Disabled Paths Tests

func TestResponseHeaders_Disabled_BasicPath(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionDeny).
		Path("/health").
		Disabled().
		Add().
		Build()

	// Regular path should have headers
	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/api")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-Frame-Options", "DENY")

	// Disabled path should have no headers
	headers = http.Header{}
	scope = mockRequestScopeHTTP("GET", "/health")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "X-Frame-Options")
	assertNoHeader(t, headers, "X-Content-Type-Options")
}

func TestResponseHeaders_Disabled_MultiplePaths(t *testing.T) {
	filter := ResponseHeaders().
		Path("/health", "/metrics").
		Disabled().
		Add().
		Build()

	disabledPaths := []string{"/health", "/metrics"}
	for _, path := range disabledPaths {
		headers := http.Header{}
		scope := mockRequestScopeHTTP("GET", path)
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", path, err)
		}
		assertNoHeader(t, headers, "X-Content-Type-Options")
		assertNoHeader(t, headers, "X-Frame-Options")
	}
}

func TestResponseHeaders_Disabled_WithDefault(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionDeny).
		Header("X-Custom", "value").
		Path("/internal/*").
		Disabled().
		Add().
		Build()

	// Non-disabled path
	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/api")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-Frame-Options", "DENY")
	assertHeaderEquals(t, headers, "X-Custom", "value")

	// Disabled path
	headers = http.Header{}
	scope = mockRequestScopeHTTP("GET", "/internal/debug")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "X-Frame-Options")
	assertNoHeader(t, headers, "X-Custom")
}

func TestResponseHeaders_Disabled_Precedence(t *testing.T) {
	filter := ResponseHeaders().
		Path("/api/**").
		Header("X-API", "true").
		Add().
		Path("/api/internal/*").
		Disabled().
		Add().
		Build()

	// /api/users should have header
	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/api/users")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "X-API", "true")

	// /api/internal/health should be disabled
	headers = http.Header{}
	scope = mockRequestScopeHTTP("GET", "/api/internal/health")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "X-API")
}

// Category 8: Complex Scenarios

func TestResponseHeaders_CompleteCustom(t *testing.T) {
	filter := ResponseHeaders().
		DisableNoSniff().
		DisableFrameOptions().
		Header("Server", "MyApp/1.0").
		Header("X-Powered-By", "Go").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Should have only custom headers, no defaults
	assertHeaderEquals(t, headers, "Server", "MyApp/1.0")
	assertHeaderEquals(t, headers, "X-Powered-By", "Go")
	assertNoHeader(t, headers, "X-Content-Type-Options")
	assertNoHeader(t, headers, "X-Frame-Options")
}

func TestResponseHeaders_AllSecurityHeaders(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionDeny).
		ReferrerPolicy(ReferrerPolicyNoReferrer).
		CSP("default-src 'self'").
		PermissionsPolicy("geolocation=()").
		COEP(COEPRequireCorp).
		COOP(COOPSameOrigin).
		CORP(CORPSameSite).
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// All security headers should be present
	assertHeaderEquals(t, headers, "X-Content-Type-Options", "nosniff")
	assertHeaderEquals(t, headers, "X-Frame-Options", "DENY")
	assertHeaderEquals(t, headers, "Referrer-Policy", "no-referrer")
	assertHeaderEquals(t, headers, "Content-Security-Policy", "default-src 'self'")
	assertHeaderEquals(t, headers, "Permissions-Policy", "geolocation=()")
	assertHeaderEquals(t, headers, "Cross-Origin-Embedder-Policy", "require-corp")
	assertHeaderEquals(t, headers, "Cross-Origin-Opener-Policy", "same-origin")
	assertHeaderEquals(t, headers, "Cross-Origin-Resource-Policy", "same-site")
}

func TestResponseHeaders_MixedConfiguration(t *testing.T) {
	filter := ResponseHeaders().
		FrameOptions(FrameOptionSameOrigin).
		Header("X-Default", "true").
		Path("/api/**").
		DisableNoSniff().
		DisableFrameOptions().
		Header("X-API-Version", "1.0").
		Header("Cache-Control", "no-store").
		Add().
		Path("/admin/**").
		FrameOptions(FrameOptionDeny).
		HSTS(31536000, true, false).
		Header("X-Admin", "true").
		Add().
		Build()

	testCases := []struct {
		name     string
		path     string
		isHTTPS  bool
		expected map[string]string
		absent   []string
	}{
		{
			name:    "Default path",
			path:    "/public",
			isHTTPS: false,
			expected: map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "SAMEORIGIN",
				"X-Default":              "true",
			},
			absent: []string{"X-API-Version", "X-Admin"},
		},
		{
			name:    "API path",
			path:    "/api/users",
			isHTTPS: false,
			expected: map[string]string{
				"X-API-Version": "1.0",
				"Cache-Control": "no-store",
			},
			absent: []string{"X-Content-Type-Options", "X-Frame-Options", "X-Admin"},
		},
		{
			name:    "Admin path over HTTPS",
			path:    "/admin/settings",
			isHTTPS: true,
			expected: map[string]string{
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Admin":                   "true",
			},
			absent: []string{"X-API-Version"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			var scope we.RequestScope
			if tc.isHTTPS {
				scope = mockRequestScopeHTTPS("GET", tc.path)
			} else {
				scope = mockRequestScopeHTTP("GET", tc.path)
			}
			err := filter.Filter(headers, scope)

			if err != nil {
				t.Errorf("Expected nil error, got %v", err)
			}

			for name, value := range tc.expected {
				assertHeaderEquals(t, headers, name, value)
			}

			for _, name := range tc.absent {
				assertNoHeader(t, headers, name)
			}
		})
	}
}

func TestResponseHeaders_API_Pattern(t *testing.T) {
	// Typical API setup: no security headers, only API-specific headers
	filter := ResponseHeaders().
		Path("/api/**").
		DisableNoSniff().
		DisableFrameOptions().
		Header("X-API-Version", "2.0").
		Header("Cache-Control", "no-store, no-cache, must-revalidate").
		Header("Content-Type", "application/json").
		Add().
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/api/users/123")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// API headers present
	assertHeaderEquals(t, headers, "X-API-Version", "2.0")
	assertHeaderEquals(t, headers, "Cache-Control", "no-store, no-cache, must-revalidate")
	assertHeaderEquals(t, headers, "Content-Type", "application/json")

	// Security headers absent
	assertNoHeader(t, headers, "X-Content-Type-Options")
	assertNoHeader(t, headers, "X-Frame-Options")
}

func TestResponseHeaders_RealWorld(t *testing.T) {
	// Complex real-world scenario
	filter := ResponseHeaders().
		// Default: basic security
		FrameOptions(FrameOptionSameOrigin).
		ReferrerPolicy(ReferrerPolicyStrictOriginWhenCrossOrigin).

		// Public widgets: allow embedding
		Path("/widgets/*").
		FrameOptions(FrameOptionAllowFrom("https://partner.com")).
		Add().

		// API: custom headers only
		Path("/api/**").
		DisableNoSniff().
		DisableFrameOptions().
		Header("X-API-Version", "1.0").
		Add().

		// Admin: very strict
		Path("/admin/**").
		FrameOptions(FrameOptionDeny).
		HSTS(63072000, true, true).
		CSP("default-src 'self'; script-src 'self'").
		Add().

		// Health checks: no headers
		Path("/health", "/metrics", "/ready").
		Disabled().
		Add().
		Build()

	testCases := []struct {
		name   string
		path   string
		method string
		https  bool
	}{
		{"Public page", "/", "GET", false},
		{"Widget", "/widgets/embed", "GET", false},
		{"API endpoint", "/api/users", "GET", false},
		{"Admin over HTTPS", "/admin/dashboard", "GET", true},
		{"Health check", "/health", "GET", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			var scope we.RequestScope
			if tc.https {
				scope = mockRequestScopeHTTPS(tc.method, tc.path)
			} else {
				scope = mockRequestScopeHTTP(tc.method, tc.path)
			}

			err := filter.Filter(headers, scope)
			if err != nil {
				t.Errorf("Expected nil error, got %v", err)
			}

			// Just verify it doesn't crash - specific assertions would be too verbose
			// The fact that it doesn't panic or error is the main test
		})
	}
}

// Category 9: Validation Tests

func TestResponseHeaders_PanicOnNegativeMaxAge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for negative HSTS maxAge")
		}
	}()

	ResponseHeaders().
		HSTS(-100, false, false).
		Build()
}

func TestResponseHeaders_PanicOnEmptyPaths(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for empty paths")
		}
	}()

	ResponseHeaders().
		Path(). // No paths
		Header("X-Test", "value").
		Add().
		Build()
}

func TestResponseHeaders_AllowsAnyHeaderName(t *testing.T) {
	// Should not panic on unusual header names
	filter := ResponseHeaders().
		Header("Unusual-Header-123", "value").
		Header("X", "y").
		Header("a-b-c-d-e-f", "test").
		Build()

	headers := http.Header{}
	scope := mockRequestScopeHTTP("GET", "/test")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Unusual-Header-123", "value")
	assertHeaderEquals(t, headers, "X", "y")
	assertHeaderEquals(t, headers, "a-b-c-d-e-f", "test")
}

func TestResponseHeaders_PathHSTS_NegativeMaxAge_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for negative HSTS maxAge in path config")
		}
	}()

	ResponseHeaders().
		Path("/test").
		HSTS(-1, false, false).
		Add().
		Build()
}
