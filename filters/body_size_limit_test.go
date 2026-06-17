// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package filters_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gomatbase/go-we/filters"
	"github.com/gomatbase/go-we/test"
)

func TestBodySizeLimit(t *testing.T) {
	t.Run("Test default max size", func(t *testing.T) {
		filter := filters.DefaultBodySizeLimit().Build()

		// Request within limit
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().ContentLength = 1000

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for request within limit, got: %v", err)
		}
	})

	t.Run("Test exceeds default max size", func(t *testing.T) {
		filter := filters.DefaultBodySizeLimit().Build()

		// Request exceeding default limit (10MB)
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().ContentLength = filters.DefaultMaxBodySize + 1

		if err := filter.Filter(nil, scope); err == nil {
			t.Error("Expected error for request exceeding limit, got nil")
		}
	})

	t.Run("Test custom max size", func(t *testing.T) {
		maxSize := int64(1024) // 1KB

		filter := filters.DefaultBodySizeLimit().
			MaxSize(maxSize).
			Build()

		// Request within custom limit
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().ContentLength = 512

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for request within custom limit, got: %v", err)
		}

		// Request exceeding custom limit
		scope = test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().ContentLength = 2048

		if err := filter.Filter(nil, scope); err == nil {
			t.Error("Expected error for request exceeding custom limit, got nil")
		}
	})

	t.Run("Test path-specific limits", func(t *testing.T) {
		filter := filters.DefaultBodySizeLimit().
			MaxSize(1024). // 1KB default
			Path("/api/upload").
			MaxSize(10485760). // 10MB for uploads
			Build()

		// Regular endpoint with default limit
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().ContentLength = 2048

		if err := filter.Filter(nil, scope); err == nil {
			t.Error("Expected error for regular endpoint exceeding limit, got nil")
		}

		// Upload endpoint with custom limit
		scope = test.MockedRequestScope(http.MethodPost, "http://localhost/api/upload")
		scope.Request().ContentLength = 5242880 // 5MB

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for upload endpoint within limit, got: %v", err)
		}

		// Upload endpoint exceeding custom limit
		scope = test.MockedRequestScope(http.MethodPost, "http://localhost/api/upload")
		scope.Request().ContentLength = 10485760 + 1

		if err := filter.Filter(nil, scope); err == nil {
			t.Error("Expected error for upload endpoint exceeding limit, got nil")
		}
	})

	t.Run("Test body reader wrapping", func(t *testing.T) {
		maxSize := int64(100)

		filter := filters.DefaultBodySizeLimit().
			MaxSize(maxSize).
			Build()

		// Create a request with body larger than limit
		body := bytes.NewBufferString(strings.Repeat("a", 200))
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().Body = io.NopCloser(body)
		scope.Request().ContentLength = 200

		// Filter should wrap the body
		if err := filter.Filter(nil, scope); err == nil {
			// Check that reading more than maxSize fails
			data, err := io.ReadAll(scope.Request().Body)
			if err == nil {
				t.Errorf("Expected error when reading body exceeding limit, got nil. Read %d bytes", len(data))
			}
		}
	})

	t.Run("Test multiple path-specific limits", func(t *testing.T) {
		filter := filters.DefaultBodySizeLimit().
			MaxSize(1024).
			Path("/api/upload", "/api/import").
			MaxSize(10485760).
			Path("/api/bulk").
			MaxSize(52428800). // 50MB
			Build()

		// Verify /api/upload limit
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/upload")
		scope.Request().ContentLength = 5242880

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for /api/upload, got: %v", err)
		}

		// Verify /api/import limit (should be same as upload)
		scope = test.MockedRequestScope(http.MethodPost, "http://localhost/api/import")
		scope.Request().ContentLength = 5242880

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for /api/import, got: %v", err)
		}

		// Verify /api/bulk limit
		scope = test.MockedRequestScope(http.MethodPost, "http://localhost/api/bulk")
		scope.Request().ContentLength = 52428800

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for /api/bulk, got: %v", err)
		}

		// Verify default limit
		scope = test.MockedRequestScope(http.MethodPost, "http://localhost/api/data")
		scope.Request().ContentLength = 2048

		if err := filter.Filter(nil, scope); err == nil {
			t.Error("Expected error for default endpoint exceeding limit, got nil")
		}
	})

	t.Run("Test zero content length", func(t *testing.T) {
		filter := filters.DefaultBodySizeLimit().
			MaxSize(1024).
			Build()

		// Request with zero content length should pass
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/api/data")
		scope.Request().ContentLength = 0

		if err := filter.Filter(nil, scope); err != nil {
			t.Errorf("Expected no error for request with zero content length, got: %v", err)
		}
	})

	t.Run("Test panic on invalid max size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for invalid max size, got nil")
			}
		}()

		filters.DefaultBodySizeLimit().
			MaxSize(-1)
	})

	t.Run("Test panic on empty paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for empty paths, got nil")
			}
		}()

		filters.DefaultBodySizeLimit().
			Path() // No paths provided
	})
}
