// Copyright 2026 GOM. All rights reserved.
// Since 01/04/2026 By GOM
// Licensed under MIT License

package filters

import (
	"net/http"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/test"
)

// Helper function to create a mock request scope
func mockRequestScope(method, path, origin string) we.RequestScope {
	url := "http://localhost" + path
	scope := test.MockedRequestScope(method, url)

	if origin != "" {
		scope.SetHeader("Origin", origin)
	}

	return scope
}

// Helper function to assert header equals expected value
func assertHeaderEquals(t *testing.T, headers http.Header, key, expected string) {
	t.Helper()
	actual := headers.Get(key)
	if actual != expected {
		t.Errorf("Header %s: expected %q, got %q", key, expected, actual)
	}
}

// Helper function to assert header contains value
func assertHeaderContains(t *testing.T, headers http.Header, key, value string) {
	t.Helper()
	actual := headers.Get(key)
	if actual != value && !contains(headers.Values(key), value) {
		t.Errorf("Header %s: expected to contain %q, got %q", key, value, actual)
	}
}

// Helper function to assert header does not exist
func assertNoHeader(t *testing.T, headers http.Header, key string) {
	t.Helper()
	if headers.Get(key) != "" {
		t.Errorf("Header %s: expected to be absent, got %q", key, headers.Get(key))
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// TestCors_DefaultValues tests that default values are set correctly
func TestCors_DefaultValues(t *testing.T) {
	builder := Cors().(*corsFilterBuilder)

	if len(builder.defaultConfig.allowedMethods) != 3 {
		t.Errorf("Default allowed methods: expected 3, got %d", len(builder.defaultConfig.allowedMethods))
	}

	expectedMethods := []string{"GET", "POST", "HEAD"}
	for i, method := range expectedMethods {
		if builder.defaultConfig.allowedMethods[i] != method {
			t.Errorf("Default method[%d]: expected %s, got %s", i, method, builder.defaultConfig.allowedMethods[i])
		}
	}

	if builder.defaultConfig.maxAge != 3600 {
		t.Errorf("Default maxAge: expected 3600, got %d", builder.defaultConfig.maxAge)
	}

	if builder.defaultConfig.allowCredentials {
		t.Error("Default allowCredentials: expected false, got true")
	}
}

// TestCors_RootLevelConfiguration tests root-level configuration
func TestCors_RootLevelConfiguration(t *testing.T) {
	builder := Cors().
		AllowedOrigins("https://example.com", "https://app.example.com").
		AllowedMethods("GET", "POST", "PUT").
		AllowedHeaders("Content-Type", "Authorization").
		ExposedHeaders("X-Request-ID").
		AllowCredentials().
		MaxAge(7200).(*corsFilterBuilder)

	if len(builder.defaultConfig.allowedOrigins) != 2 {
		t.Errorf("AllowedOrigins: expected 2, got %d", len(builder.defaultConfig.allowedOrigins))
	}

	if len(builder.defaultConfig.allowedMethods) != 3 {
		t.Errorf("AllowedMethods: expected 3, got %d", len(builder.defaultConfig.allowedMethods))
	}

	if !builder.defaultConfig.allowCredentials {
		t.Error("AllowCredentials: expected true, got false")
	}

	if builder.defaultConfig.maxAge != 7200 {
		t.Errorf("MaxAge: expected 7200, got %d", builder.defaultConfig.maxAge)
	}
}

// TestCors_PathSpecificConfiguration tests path-specific configuration
func TestCors_PathSpecificConfiguration(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/*").
		AllowedOrigins("*").
		AllowedMethods("GET").
		Add().
		Build()

	if filter == nil {
		t.Fatal("Build() returned nil")
	}
}

// TestCors_MultiplePathConfigs tests multiple path configurations
func TestCors_MultiplePathConfigs(t *testing.T) {
	builder := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/public/*").
		AllowedOrigins("*").
		Add().
		Path("/api/admin/*").
		AllowedOrigins("https://admin.example.com").
		AllowCredentials().
		Add().(*corsFilterBuilder)

	if len(builder.pathConfigs) != 2 {
		t.Errorf("PathConfigs: expected 2, got %d", len(builder.pathConfigs))
	}
}

// TestCors_PanicOnEmptyOrigins tests panic when no origins provided
func TestCors_PanicOnEmptyOrigins(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling AllowedOrigins with empty list")
		}
	}()

	Cors().AllowedOrigins()
}

// TestCors_PanicOnEmptyMethods tests panic when no methods provided
func TestCors_PanicOnEmptyMethods(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling AllowedMethods with empty list")
		}
	}()

	Cors().AllowedMethods()
}

// TestCors_PanicOnEmptyHeaders tests panic when no headers provided
func TestCors_PanicOnEmptyHeaders(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling AllowedHeaders with empty list")
		}
	}()

	Cors().AllowedHeaders()
}

// TestCors_PanicOnEmptyPaths tests panic when no paths provided to Path()
func TestCors_PanicOnEmptyPaths(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling Path with empty list")
		}
	}()

	Cors().Path()
}

// TestCors_PanicOnNegativeMaxAge tests panic when negative maxAge provided
func TestCors_PanicOnNegativeMaxAge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling MaxAge with negative value")
		}
	}()

	Cors().MaxAge(-1)
}

// TestCors_PanicOnCredentialsWithWildcard tests panic when credentials used with wildcard
func TestCors_PanicOnCredentialsWithWildcard(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when using AllowCredentials with wildcard origin")
		}
	}()

	Cors().
		AllowedOrigins("*").
		AllowCredentials().
		Build()
}

// TestCors_PanicOnNoConfiguration tests panic when no configuration provided
func TestCors_PanicOnNoConfiguration(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when building with no configuration")
		}
	}()

	Cors().Build()
}

// TestCorsFilter_NoOriginHeader tests that filter skips when no Origin header
func TestCorsFilter_NoOriginHeader(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "")

	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertNoHeader(t, headers, "Access-Control-Allow-Origin")
}

// TestCorsFilter_AllowedOrigin tests allowed origin handling
func TestCorsFilter_AllowedOrigin(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com", "https://app.example.com").
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")

	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "https://example.com")
	assertHeaderContains(t, headers, "Vary", "Origin")
}

// TestCorsFilter_DeniedOrigin tests denied origin handling
func TestCorsFilter_DeniedOrigin(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://evil.com")

	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertNoHeader(t, headers, "Access-Control-Allow-Origin")
}

// TestCorsFilter_WildcardOrigin tests wildcard origin handling
func TestCorsFilter_WildcardOrigin(t *testing.T) {
	filter := Cors().
		AllowedOrigins("*").
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")

	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "*")
	// Wildcard should not have Vary header
	if headers.Get("Vary") != "" {
		t.Error("Wildcard origin should not set Vary header")
	}
}

// TestCorsFilter_CredentialsHeader tests credentials header
func TestCorsFilter_CredentialsHeader(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		AllowCredentials().
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")

	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Access-Control-Allow-Credentials", "true")
}

// TestCorsFilter_ExposedHeaders tests exposed headers
func TestCorsFilter_ExposedHeaders(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		ExposedHeaders("X-Request-ID", "X-RateLimit-Remaining").
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")

	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	exposedHeaders := headers.Get("Access-Control-Expose-Headers")
	if exposedHeaders != "X-Request-ID, X-RateLimit-Remaining" {
		t.Errorf("ExposedHeaders: expected %q, got %q", "X-Request-ID, X-RateLimit-Remaining", exposedHeaders)
	}
}

// TestCorsFilter_PreflightRequest tests OPTIONS preflight request
func TestCorsFilter_PreflightRequest(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST", "PUT").
		AllowedHeaders("Content-Type", "Authorization").
		MaxAge(7200).
		Build()

	headers := http.Header{}
	scope := mockRequestScope("OPTIONS", "/api/test", "https://example.com")

	err := filter.Filter(headers, scope)

	// Should return Update event with 204
	if err == nil {
		t.Fatal("Expected error (WeEvent), got nil")
	}

	weEvent, ok := err.(events.WeEvent)
	if !ok {
		t.Fatalf("Expected WeEvent, got %T", err)
	}

	if weEvent.StatusCode() != http.StatusNoContent {
		t.Errorf("Status code: expected %d, got %d", http.StatusNoContent, weEvent.StatusCode())
	}

	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "https://example.com")
	assertHeaderEquals(t, headers, "Access-Control-Allow-Methods", "GET, POST, PUT")
	assertHeaderEquals(t, headers, "Access-Control-Allow-Headers", "Content-Type, Authorization")
	assertHeaderEquals(t, headers, "Access-Control-Max-Age", "7200")
}

// TestCorsFilter_PathSpecificConfig tests path-specific CORS config
func TestCorsFilter_PathSpecificConfig(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/public/*").
		AllowedOrigins("*").
		Add().
		Build()

	// Test root path - uses root config
	headers := http.Header{}
	scope := mockRequestScope("GET", "/other/test", "https://example.com")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "https://example.com")

	// Test path-specific - uses path config
	headers = http.Header{}
	scope = mockRequestScope("GET", "/api/public/data", "https://anyorigin.com")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "*")
}

// TestCorsFilter_WildcardPathMatching tests wildcard path matching
func TestCorsFilter_WildcardPathMatching(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/*").
		AllowedOrigins("*").
		Add().
		Build()

	testCases := []struct {
		path           string
		expectedOrigin string
	}{
		{"/api/users", "*"},
		{"/api/posts", "*"},
		{"/other/path", "https://example.com"},
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScope("GET", tc.path, "https://example.com")
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}

		assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", tc.expectedOrigin)
	}
}

// TestCorsFilter_DoubleWildcardMatching tests double wildcard path matching
func TestCorsFilter_DoubleWildcardMatching(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/**").
		AllowedOrigins("*").
		Add().
		Build()

	testCases := []struct {
		path           string
		expectedOrigin string
	}{
		{"/api/users", "*"},
		{"/api/users/123", "*"},
		{"/api/users/123/profile", "*"},
		{"/other/path", "https://example.com"},
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScope("GET", tc.path, "https://example.com")
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}

		assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", tc.expectedOrigin)
	}
}

// TestCorsFilter_PathPrecedence tests that most specific path wins
func TestCorsFilter_PathPrecedence(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/**").
		AllowedOrigins("https://api.example.com").
		Add().
		Path("/api/public/*").
		AllowedOrigins("*").
		Add().
		Build()

	testCases := []struct {
		path           string
		expectedOrigin string
	}{
		{"/api/public/data", "*"}, // Most specific
		{"/api/users/123", "https://api.example.com"},
		{"/other/path", "https://example.com"}, // Root config
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScope("GET", tc.path, tc.expectedOrigin)
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}

		assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", tc.expectedOrigin)
	}
}

// TestCorsFilter_FallbackToRoot tests fallback to root config
func TestCorsFilter_FallbackToRoot(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/*").
		AllowedOrigins("*").
		Add().
		Build()

	headers := http.Header{}
	scope := mockRequestScope("GET", "/other/path", "https://example.com")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "https://example.com")
}

// TestCorsFilter_NoRootConfigPathOnly tests path-only config (no root)
func TestCorsFilter_NoRootConfigPathOnly(t *testing.T) {
	filter := Cors().
		Path("/api/*").
		AllowedOrigins("*").
		Add().
		Build()

	// Path matching /api/* should get CORS
	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "*")

	// Path not matching should get no CORS
	headers = http.Header{}
	scope = mockRequestScope("GET", "/other/test", "https://example.com")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "Access-Control-Allow-Origin")
}

// TestCorsFilter_ComplexScenario tests a complex real-world scenario
func TestCorsFilter_ComplexScenario(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").
		Path("/api/public/*").
		AllowedOrigins("*").
		AllowedMethods("GET").
		Add().
		Path("/api/admin/**").
		AllowedOrigins("https://admin.example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowCredentials().
		Add().
		Build()

	testCases := []struct {
		name           string
		path           string
		origin         string
		method         string
		expectOrigin   string
		expectNoHeader bool
	}{
		{"Public API - any origin", "/api/public/data", "https://anyorigin.com", "GET", "*", false},
		{"Admin API - allowed origin", "/api/admin/users", "https://admin.example.com", "GET", "https://admin.example.com", false},
		{"Admin API - denied origin", "/api/admin/users", "https://evil.com", "GET", "", true},
		{"Root path", "/home", "https://example.com", "GET", "https://example.com", false},
		{"Root path - denied", "/home", "https://evil.com", "GET", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			scope := mockRequestScope(tc.method, tc.path, tc.origin)
			err := filter.Filter(headers, scope)

			if err != nil {
				t.Errorf("Expected nil error, got %v", err)
			}

			if tc.expectNoHeader {
				assertNoHeader(t, headers, "Access-Control-Allow-Origin")
			} else {
				assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", tc.expectOrigin)
			}
		})
	}
}

// TestCorsFilter_MultiplePathsInOneConfig tests multiple paths in one Path() call
func TestCorsFilter_MultiplePathsInOneConfig(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/v1/*", "/api/v2/*").
		AllowedOrigins("*").
		Add().
		Build()

	testCases := []struct {
		path           string
		expectedOrigin string
	}{
		{"/api/v1/users", "*"},
		{"/api/v2/users", "*"},
		{"/api/v3/users", "https://example.com"},
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScope("GET", tc.path, "https://example.com")
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}

		assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", tc.expectedOrigin)
	}
}

// TestCorsFilter_Disabled tests explicitly disabled CORS for specific paths
func TestCorsFilter_Disabled(t *testing.T) {
	filter := Cors().
		// Default: enable CORS
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").
		// Disable CORS for internal paths
		Path("/internal/*").
		Disabled().
		Add().
		Build()

	// Regular path should get CORS headers
	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "https://example.com")

	// Internal path should NOT get CORS headers (disabled)
	headers = http.Header{}
	scope = mockRequestScope("GET", "/internal/health", "https://example.com")
	err = filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "Access-Control-Allow-Origin")
}

// TestCorsFilter_DisabledMultiplePaths tests disabled CORS for multiple paths
func TestCorsFilter_DisabledMultiplePaths(t *testing.T) {
	filter := Cors().
		AllowedOrigins("*").
		AllowedMethods("GET", "POST").
		Path("/internal/*", "/health").
		Disabled().
		Add().
		Build()

	testCases := []struct {
		path           string
		shouldHaveCors bool
	}{
		{"/api/users", true},
		{"/internal/metrics", false},
		{"/internal/debug", false},
		{"/health", false},
		{"/public/data", true},
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScope("GET", tc.path, "https://example.com")
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}

		if tc.shouldHaveCors {
			assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "*")
		} else {
			assertNoHeader(t, headers, "Access-Control-Allow-Origin")
		}
	}
}

// TestCorsFilter_DisabledWithWildcard tests disabled CORS with wildcard paths
func TestCorsFilter_DisabledWithWildcard(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/admin/**").
		Disabled().
		Add().
		Build()

	// Admin paths should have CORS disabled
	testPaths := []string{
		"/admin/users",
		"/admin/users/123",
		"/admin/settings/security",
	}

	for _, path := range testPaths {
		headers := http.Header{}
		scope := mockRequestScope("GET", path, "https://example.com")
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", path, err)
		}
		assertNoHeader(t, headers, "Access-Control-Allow-Origin")
	}

	// Other paths should still have CORS enabled
	headers := http.Header{}
	scope := mockRequestScope("GET", "/api/test", "https://example.com")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "https://example.com")
}

// TestCorsFilter_DisabledPreflight tests that preflight requests are also disabled
func TestCorsFilter_DisabledPreflight(t *testing.T) {
	filter := Cors().
		AllowedOrigins("*").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		Path("/internal/*").
		Disabled().
		Add().
		Build()

	// OPTIONS request to disabled path should NOT get CORS headers or 204 response
	headers := http.Header{}
	scope := mockRequestScope("OPTIONS", "/internal/health", "https://example.com")
	err := filter.Filter(headers, scope)

	// Should return nil (no preflight handling)
	if err != nil {
		t.Errorf("Expected nil error for disabled preflight, got %v", err)
	}
	assertNoHeader(t, headers, "Access-Control-Allow-Origin")
	assertNoHeader(t, headers, "Access-Control-Allow-Methods")

	// OPTIONS request to enabled path should get 204 and CORS headers
	headers = http.Header{}
	scope = mockRequestScope("OPTIONS", "/api/test", "https://example.com")
	err = filter.Filter(headers, scope)

	// Should return 204 event
	if err == nil {
		t.Error("Expected 204 event for enabled preflight, got nil")
	}
	assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", "*")
	// Verify Allow-Methods header is present
	if headers.Get("Access-Control-Allow-Methods") == "" {
		t.Error("Expected Access-Control-Allow-Methods header for enabled preflight")
	}
}

// TestCorsFilter_DisabledNoValidationRequired tests that disabled configs skip validation
func TestCorsFilter_DisabledNoValidationRequired(t *testing.T) {
	// This should NOT panic even though we're not setting AllowedOrigins
	// because disabled configs skip validation
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Disabled config should not require validation, but panicked: %v", r)
		}
	}()

	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/disabled/*").
		Disabled().
		Add().
		Build()

	// Verify it works
	headers := http.Header{}
	scope := mockRequestScope("GET", "/disabled/test", "https://example.com")
	err := filter.Filter(headers, scope)

	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	assertNoHeader(t, headers, "Access-Control-Allow-Origin")
}

// TestCorsFilter_DisabledPathPrecedence tests that disabled paths take precedence
func TestCorsFilter_DisabledPathPrecedence(t *testing.T) {
	filter := Cors().
		AllowedOrigins("https://example.com").
		Path("/api/**").
		AllowedOrigins("*").
		Add().
		// More specific: disable CORS for /api/internal/*
		Path("/api/internal/*").
		Disabled().
		Add().
		Build()

	testCases := []struct {
		path           string
		shouldHaveCors bool
		expectedOrigin string
	}{
		{"/api/users", true, "*"},
		{"/api/posts/123", true, "*"},
		{"/api/internal/health", false, ""},
		{"/api/internal/metrics", false, ""},
		{"/other", true, "https://example.com"},
	}

	for _, tc := range testCases {
		headers := http.Header{}
		scope := mockRequestScope("GET", tc.path, "https://example.com")
		err := filter.Filter(headers, scope)

		if err != nil {
			t.Errorf("Path %s: expected nil error, got %v", tc.path, err)
		}

		if tc.shouldHaveCors {
			assertHeaderEquals(t, headers, "Access-Control-Allow-Origin", tc.expectedOrigin)
		} else {
			assertNoHeader(t, headers, "Access-Control-Allow-Origin")
		}
	}
}
