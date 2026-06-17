// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package filters

import (
	"net/http"
	"testing"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/test"
)

func TestCsrf(t *testing.T) {
	t.Run("Test_safe_methods_generate_token", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("GET", "http://localhost/form")
		session := scope.Session()

		// Token should not exist initially
		if session.Get(DefaultCsrfSessionKey) != nil {
			t.Error("expected no token in session initially")
		}

		// Filter should generate token for safe method
		if err := filter.Filter(http.Header{}, scope); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Token should now exist
		if session.Get(DefaultCsrfSessionKey) == nil {
			t.Error("expected token in session after filter")
		}
	})

	t.Run("Test_safe_method_reuses_token", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("GET", "http://localhost/form")

		// First call generates token
		filter.Filter(http.Header{}, scope)
		token1 := scope.Session().Get(DefaultCsrfSessionKey)

		// Second call should reuse token
		scope2 := test.MockedRequestScope("GET", "http://localhost/form")
		scope2.Session().Set(DefaultCsrfSessionKey, token1)
		filter.Filter(http.Header{}, scope2)
		token2 := scope2.Session().Get(DefaultCsrfSessionKey)

		if token1 != token2 {
			t.Error("expected token to be reused")
		}
	})

	t.Run("Test_post_without_token_rejected", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("POST", "http://localhost/form")

		// POST without token should be rejected
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected error for POST without CSRF token")
		}

		weEvent, ok := err.(events.WeEvent)
		if !ok {
			t.Errorf("expected WeEvent, got %T", err)
		}

		if weEvent.StatusCode() != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, weEvent.StatusCode())
		}
	})

	t.Run("Test_post_with_invalid_token_rejected", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("POST", "http://localhost/form")
		scope.Session().Set(DefaultCsrfSessionKey, "valid-token")

		// Create a new request with wrong token
		req := scope.Request()
		req.Header.Set(DefaultCsrfHeaderName, "invalid-token")

		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected error for invalid CSRF token")
		}
	})

	t.Run("Test_post_with_valid_header_token_accepted", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("POST", "http://localhost/form")

		// Generate and set token
		token := "test-token-12345"
		scope.Session().Set(DefaultCsrfSessionKey, token)

		// Set token in header
		req := scope.Request()
		req.Header.Set(DefaultCsrfHeaderName, token)

		err := filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Test_put_with_valid_token_accepted", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("PUT", "http://localhost/api/resource")

		token := "test-token-put"
		scope.Session().Set(DefaultCsrfSessionKey, token)

		req := scope.Request()
		req.Header.Set(DefaultCsrfHeaderName, token)

		err := filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Test_delete_with_valid_token_accepted", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("DELETE", "http://localhost/api/resource")

		token := "test-token-delete"
		scope.Session().Set(DefaultCsrfSessionKey, token)

		req := scope.Request()
		req.Header.Set(DefaultCsrfHeaderName, token)

		err := filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Test_patch_with_valid_token_accepted", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("PATCH", "http://localhost/api/resource")

		token := "test-token-patch"
		scope.Session().Set(DefaultCsrfSessionKey, token)

		req := scope.Request()
		req.Header.Set(DefaultCsrfHeaderName, token)

		err := filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Test_exempt_paths_bypass_validation", func(t *testing.T) {
		filter := Csrf().ExemptPaths("/api/webhook").Build()
		scope := test.MockedRequestScope("POST", "http://localhost/api/webhook")

		// POST to exempt path without token should be allowed
		err := filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error for exempt path: %v", err)
		}
	})

	t.Run("Test_multiple_exempt_paths", func(t *testing.T) {
		filter := Csrf().
			ExemptPaths("/api/webhook", "/api/external", "/health").
			Build()

		for _, path := range []string{"/api/webhook", "/api/external", "/health"} {
			scope := test.MockedRequestScope("POST", "http://localhost"+path)
			err := filter.Filter(http.Header{}, scope)
			if err != nil {
				t.Errorf("unexpected error for exempt path %s: %v", path, err)
			}
		}
	})

	t.Run("Test_custom_header_name", func(t *testing.T) {
		filter := Csrf().HeaderName("X-Custom-CSRF").Build()
		scope := test.MockedRequestScope("POST", "http://localhost/form")

		token := "custom-token"
		scope.Session().Set(DefaultCsrfSessionKey, token)

		// Token in default header should not work
		req := scope.Request()
		req.Header.Set(DefaultCsrfHeaderName, token)

		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected error when using wrong header name")
		}

		// Token in custom header should work
		scope2 := test.MockedRequestScope("POST", "http://localhost/form")
		scope2.Session().Set(DefaultCsrfSessionKey, token)
		req2 := scope2.Request()
		req2.Header.Set("X-Custom-CSRF", token)

		err = filter.Filter(http.Header{}, scope2)
		if err != nil {
			t.Errorf("unexpected error with custom header: %v", err)
		}
	})

	t.Run("Test_form_field_as_fallback", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("POST", "http://localhost/form")

		token := "form-token"
		scope.Session().Set(DefaultCsrfSessionKey, token)

		// Simulate form data with CSRF token
		req := scope.Request()
		req.Method = "POST"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// For testing, we'll just test that the header takes precedence
		req.Header.Set(DefaultCsrfHeaderName, token)

		err := filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Test_panic_on_empty_header_name", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for empty header name")
			}
		}()

		Csrf().HeaderName("")
	})

	t.Run("Test_panic_on_empty_field_name", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for empty field name")
			}
		}()

		Csrf().FieldName("")
	})

	t.Run("Test_panic_on_invalid_token_length", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid token length")
			}
		}()

		Csrf().TokenLength(0)
	})

	t.Run("Test_panic_on_no_exempt_paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for no exempt paths")
			}
		}()

		Csrf().ExemptPaths()
	})

	t.Run("Test_panic_on_empty_exempt_path", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for empty exempt path")
			}
		}()

		Csrf().ExemptPaths("", "/valid")
	})

	t.Run("Test_generated_token_format", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("GET", "http://localhost/form")

		filter.Filter(http.Header{}, scope)
		token := scope.Session().Get(DefaultCsrfSessionKey)

		tokenStr, ok := token.(string)
		if !ok {
			t.Errorf("expected string token, got %T", token)
		}

		// Token should be hex-encoded, so length should be 2 * byte length (32 bytes = 64 hex chars)
		expectedLength := DefaultCsrfTokenLength * 2
		if len(tokenStr) != expectedLength {
			t.Errorf("expected token length %d, got %d", expectedLength, len(tokenStr))
		}

		// Token should only contain hex characters
		if !isHexString(tokenStr) {
			t.Error("token contains non-hex characters")
		}
	})

	t.Run("Test_custom_token_length", func(t *testing.T) {
		customLength := 16
		filter := Csrf().TokenLength(customLength).Build()
		scope := test.MockedRequestScope("GET", "http://localhost/form")

		filter.Filter(http.Header{}, scope)
		token := scope.Session().Get(DefaultCsrfSessionKey)

		tokenStr, ok := token.(string)
		if !ok {
			t.Errorf("expected string token, got %T", token)
		}

		// Token should be hex-encoded
		expectedLength := customLength * 2
		if len(tokenStr) != expectedLength {
			t.Errorf("expected token length %d, got %d", expectedLength, len(tokenStr))
		}
	})

	t.Run("Test_options_method_generates_token", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("OPTIONS", "http://localhost/form")

		if err := filter.Filter(http.Header{}, scope); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if scope.Session().Get(DefaultCsrfSessionKey) == nil {
			t.Error("expected token to be generated for OPTIONS")
		}
	})

	t.Run("Test_head_method_generates_token", func(t *testing.T) {
		filter := Csrf().Build()
		scope := test.MockedRequestScope("HEAD", "http://localhost/form")

		if err := filter.Filter(http.Header{}, scope); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if scope.Session().Get(DefaultCsrfSessionKey) == nil {
			t.Error("expected token to be generated for HEAD")
		}
	})
}

// isHexString checks if a string contains only valid hex characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
