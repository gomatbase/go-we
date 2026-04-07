// Copyright 2026 GOM. All rights reserved.
// Since 04/04/2026 By GOM
// Licensed under MIT License

package we_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

func TestErrorMarshallerFunction(t *testing.T) {
	t.Run("Custom marshaller returns body and mime type", func(t *testing.T) {
		marshaller := we.ErrorMarshallerFunction(func(err error) ([]byte, string) {
			return []byte(`{"error":"` + err.Error() + `"}`), "application/json"
		})

		err := errors.New("test error")
		body, mimeType := marshaller.Marshal(err)

		if string(body) != `{"error":"test error"}` {
			t.Errorf("Expected JSON error body, got %s", body)
		}
		if mimeType != "application/json" {
			t.Errorf("Expected application/json mime type, got %s", mimeType)
		}
	})
}

func TestDefaultErrorMarshaller(t *testing.T) {
	t.Run("WeEvent with payload returns payload content", func(t *testing.T) {
		payload := &events.Payload{
			ContentTypeHint: "text/plain",
			Content:         []byte("Error occurred"),
		}
		err := events.NewPayload(400, "Bad Request", payload)

		// Create engine with default error handling
		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return err
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		engine.Handler().ServeHTTP(w, req)

		if w.Code != 400 {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if w.Body.String() != "Error occurred" {
			t.Errorf("Expected 'Error occurred', got %s", w.Body.String())
		}
		if w.Header().Get("Content-Type") != "text/plain" {
			t.Errorf("Expected Content-Type text/plain, got %s", w.Header().Get("Content-Type"))
		}

		_ = shutdown()
	})

	t.Run("WeEvent without payload returns empty body", func(t *testing.T) {
		err := events.New(404, "Not Found")

		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return err
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		engine.Handler().ServeHTTP(w, req)

		if w.Code != 404 {
			t.Errorf("Expected status 404, got %d", w.Code)
		}
		if w.Body.Len() != 0 {
			t.Errorf("Expected empty body, got %s", w.Body.String())
		}

		_ = shutdown()
	})

	t.Run("Regular error returns 500 with empty body", func(t *testing.T) {
		err := errors.New("regular error")

		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return err
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		engine.Handler().ServeHTTP(w, req)

		if w.Code != 500 {
			t.Errorf("Expected status 500, got %d", w.Code)
		}
		if w.Body.Len() != 0 {
			t.Errorf("Expected empty body, got %s", w.Body.String())
		}

		_ = shutdown()
	})
}

func TestErrorHandlerAfterWriteStarted(t *testing.T) {
	t.Run("Error after response started is logged but not sent", func(t *testing.T) {
		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			// Start writing response
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial response"))

			// Then return an error
			return events.New(500, "Error after write")
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		engine.Handler().ServeHTTP(w, req)

		// Should still have 200 status since write already started
		if w.Code != 200 {
			t.Errorf("Expected status 200 (already written), got %d", w.Code)
		}
		if w.Body.String() != "partial response" {
			t.Errorf("Expected 'partial response', got %s", w.Body.String())
		}

		_ = shutdown()
	})
}

func TestErrorHandlerIntegration(t *testing.T) {
	t.Run("Different error types handled correctly", func(t *testing.T) {
		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		// Handler that returns different error types based on path
		engine.Handle("/badrequest", func(w http.ResponseWriter, r we.RequestScope) error {
			return events.NewPayload(400, "Bad Request", &events.Payload{
				ContentTypeHint: "application/json",
				Content:         []byte(`{"error":"invalid input"}`),
			})
		})

		engine.Handle("/unauthorized", func(w http.ResponseWriter, r we.RequestScope) error {
			return events.New(401, "Unauthorized")
		})

		engine.Handle("/servererror", func(w http.ResponseWriter, r we.RequestScope) error {
			return errors.New("internal error")
		})

		engine.Handle("/panic", func(w http.ResponseWriter, r we.RequestScope) error {
			panic("something went wrong")
		})

		// Test 400 with payload
		req := httptest.NewRequest(http.MethodGet, "/badrequest", nil)
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 400 {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if w.Body.String() != `{"error":"invalid input"}` {
			t.Errorf("Expected JSON body, got %s", w.Body.String())
		}

		// Test 401 without payload
		req = httptest.NewRequest(http.MethodGet, "/unauthorized", nil)
		w = httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 401 {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
		if w.Body.Len() != 0 {
			t.Errorf("Expected empty body, got %s", w.Body.String())
		}

		// Test regular error
		req = httptest.NewRequest(http.MethodGet, "/servererror", nil)
		w = httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 500 {
			t.Errorf("Expected status 500, got %d", w.Code)
		}

		// Test panic recovery
		req = httptest.NewRequest(http.MethodGet, "/panic", nil)
		w = httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 500 {
			t.Errorf("Expected status 500 for panic, got %d", w.Code)
		}

		_ = shutdown()
	})
}

func TestErrorHandlerWithFilters(t *testing.T) {
	t.Run("Filter errors are handled correctly", func(t *testing.T) {
		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		// Filter that returns an error
		engine.AddFilter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			if r.Parameter("fail") == "true" {
				return events.NewPayload(403, "Forbidden", &events.Payload{
					ContentTypeHint: "text/plain",
					Content:         []byte("Access denied"),
				})
			}
			return nil
		}))

		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			_, _ = w.Write([]byte("success"))
			return nil
		})

		// Request that passes filter
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		if w.Body.String() != "success" {
			t.Errorf("Expected 'success', got %s", w.Body.String())
		}

		// Request that fails filter
		req = httptest.NewRequest(http.MethodGet, "/?fail=true", nil)
		w = httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 403 {
			t.Errorf("Expected status 403, got %d", w.Code)
		}
		if w.Body.String() != "Access denied" {
			t.Errorf("Expected 'Access denied', got %s", w.Body.String())
		}

		_ = shutdown()
	})
}

func TestErrorHandlerEdgeCases(t *testing.T) {
	t.Run("Multiple errors in sequence", func(t *testing.T) {
		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		errorCount := 0
		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			errorCount++
			if errorCount%2 == 0 {
				return events.New(404, "Not Found")
			}
			return events.New(500, "Server Error")
		})

		// First request - should get 500
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
		if w.Code != 500 {
			t.Errorf("First request: expected 500, got %d", w.Code)
		}

		// Second request - should get 404
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		w = httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
		if w.Code != 404 {
			t.Errorf("Second request: expected 404, got %d", w.Code)
		}

		_ = shutdown()
	})

	t.Run("Error with attributes", func(t *testing.T) {
		engine := we.New()
		var shutdown func() error
		engine.HookShutdownFunction(&shutdown)

		engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return events.New(400, "Validation Error").WithAttribute("field:username")
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)

		if w.Code != 400 {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		_ = shutdown()
	})
}
