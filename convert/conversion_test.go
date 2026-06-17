// Copyright 2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package convert_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gomatbase/go-we/convert"
	"github.com/gomatbase/go-we/test"
)

type testHandler struct {
	called  bool
	method  string
	url     string
	headers http.Header
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.method = r.Method
	h.url = r.URL.String()
	h.headers = r.Header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("handler-response"))
}

func TestHandler(t *testing.T) {
	t.Run("wraps http.Handler and delegates correctly", func(t *testing.T) {
		h := &testHandler{}
		wrapped := convert.Handler(h)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/test")

		err := wrapped(recorder, scope)
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
		if !h.called {
			t.Error("expected handler ServeHTTP to be called")
		}
	})

	t.Run("passes request from scope to handler", func(t *testing.T) {
		h := &testHandler{}
		wrapped := convert.Handler(h)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost/api/resource")

		_ = wrapped(recorder, scope)

		if h.method != http.MethodPost {
			t.Errorf("expected method POST, got %s", h.method)
		}
		if h.url != "http://localhost/api/resource" {
			t.Errorf("expected url http://localhost/api/resource, got %s", h.url)
		}
	})

	t.Run("passes request headers through", func(t *testing.T) {
		h := &testHandler{}
		wrapped := convert.Handler(h)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/test")
		scope.SetHeader("X-Custom-Header", "custom-value")

		_ = wrapped(recorder, scope)

		if h.headers.Get("X-Custom-Header") != "custom-value" {
			t.Errorf("expected X-Custom-Header to be 'custom-value', got %q", h.headers.Get("X-Custom-Header"))
		}
	})

	t.Run("response writer receives written data", func(t *testing.T) {
		h := &testHandler{}
		wrapped := convert.Handler(h)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/test")

		_ = wrapped(recorder, scope)

		if recorder.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", recorder.Code)
		}
		body := recorder.Body.String()
		if body != "handler-response" {
			t.Errorf("expected body 'handler-response', got %q", body)
		}
	})
}

func TestHandlerFunc(t *testing.T) {
	t.Run("wraps http.HandlerFunc and delegates correctly", func(t *testing.T) {
		called := false
		handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("func-response"))
		})

		wrapped := convert.HandlerFunc(handlerFunc)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/test")

		err := wrapped(recorder, scope)
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
		if !called {
			t.Error("expected handler function to be called")
		}
	})

	t.Run("passes request from scope to handler func", func(t *testing.T) {
		var capturedMethod string
		var capturedURL string
		handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedMethod = r.Method
			capturedURL = r.URL.String()
		})

		wrapped := convert.HandlerFunc(handlerFunc)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodPut, "http://localhost/api/items/42")

		_ = wrapped(recorder, scope)

		if capturedMethod != http.MethodPut {
			t.Errorf("expected method PUT, got %s", capturedMethod)
		}
		if capturedURL != "http://localhost/api/items/42" {
			t.Errorf("expected url http://localhost/api/items/42, got %s", capturedURL)
		}
	})

	t.Run("passes request headers through", func(t *testing.T) {
		var capturedHeaders http.Header
		handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeaders = r.Header
		})

		wrapped := convert.HandlerFunc(handlerFunc)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/test")
		scope.SetHeader("Authorization", "Bearer token123")

		_ = wrapped(recorder, scope)

		if capturedHeaders.Get("Authorization") != "Bearer token123" {
			t.Errorf("expected Authorization header 'Bearer token123', got %q", capturedHeaders.Get("Authorization"))
		}
	})

	t.Run("response writer receives written data", func(t *testing.T) {
		handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("func-response"))
		})

		wrapped := convert.HandlerFunc(handlerFunc)

		recorder := httptest.NewRecorder()
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost/test")

		_ = wrapped(recorder, scope)

		if recorder.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d", recorder.Code)
		}
		body := recorder.Body.String()
		if body != "func-response" {
			t.Errorf("expected body 'func-response', got %q", body)
		}
	})
}
