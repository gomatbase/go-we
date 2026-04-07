// Copyright 2026 GOM. All rights reserved.
// Since 07/04/2026 By GOM
// Licensed under MIT License

package we_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/filters"
	"github.com/gomatbase/go-we/security"
)

// BenchmarkSimpleHandler benchmarks a simple handler with no filters
func BenchmarkSimpleHandler(b *testing.B) {
	engine := we.New()
	engine.Handle("/test", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithPathVariable benchmarks handler with path variable extraction
func BenchmarkHandlerWithPathVariable(b *testing.B) {
	engine := we.New()
	engine.Handle("/users/{id}/posts/{postId}", func(w http.ResponseWriter, r we.RequestScope) error {
		userId := r.Var("id")
		postId := r.Var("postId")
		w.Write([]byte(userId + ":" + postId))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/users/123/posts/456", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithQueryParams benchmarks handler with query parameter extraction
func BenchmarkHandlerWithQueryParams(b *testing.B) {
	engine := we.New()
	engine.Handle("/search", func(w http.ResponseWriter, r we.RequestScope) error {
		q := r.Parameter("q")
		page := r.Parameter("page")
		w.Write([]byte(q + ":" + page))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/search?q=golang&page=2", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithSingleFilter benchmarks handler with one filter
func BenchmarkHandlerWithSingleFilter(b *testing.B) {
	engine := we.New()

	engine.AddFilter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
		h.Set("X-Custom-Header", "test")
		return nil
	}))

	engine.Handle("/test", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithMultipleFilters benchmarks handler with multiple filters
func BenchmarkHandlerWithMultipleFilters(b *testing.B) {
	engine := we.New()

	// Add 5 filters
	for j := 0; j < 5; j++ {
		engine.AddFilter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			return nil
		}))
	}

	engine.Handle("/test", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithSession benchmarks handler with session management
func BenchmarkHandlerWithSession(b *testing.B) {
	engine := we.New()
	sessionManager := we.DefaultSessionManager().Build()
	engine.SetSessionManager(sessionManager)

	engine.Handle("/test", func(w http.ResponseWriter, r we.RequestScope) error {
		r.SetInSession("key", "value")
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithCORS benchmarks handler with CORS filter
func BenchmarkHandlerWithCORS(b *testing.B) {
	engine := we.New()

	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com").
		AllowedMethods("GET", "POST").
		AllowedHeaders("Content-Type").
		Build()

	engine.AddFilter(corsFilter)

	engine.Handle("/api/data", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Origin", "https://example.com")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkHandlerWithBasicAuth benchmarks handler with basic authentication
func BenchmarkHandlerWithBasicAuth(b *testing.B) {
	engine := we.New()

	user := security.User{
		Username: "testuser",
		Password: "testpass",
		Scopes:   []string{"user"},
	}

	authProvider := security.BasicAuthenticationProvider(user).Build()
	secFilter := security.Filter(false).
		Path("/api/**").
		Authentication(authProvider).
		Authorize().
		Build()

	engine.AddFilter(secFilter)

	engine.Handle("/api/data", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.SetBasicAuth("testuser", "testpass")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkErrorHandling benchmarks error handling in handlers
func BenchmarkErrorHandling(b *testing.B) {
	engine := we.New()

	engine.Handle("/error", func(w http.ResponseWriter, r we.RequestScope) error {
		return events.BadRequestError
	})

	req := httptest.NewRequest(http.MethodGet, "/error", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkPathMatching benchmarks different path matching scenarios
func BenchmarkPathMatchingStatic(b *testing.B) {
	engine := we.New()
	engine.Handle("/api/users", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

func BenchmarkPathMatchingWithVariable(b *testing.B) {
	engine := we.New()
	engine.Handle("/api/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
		_ = r.Var("id")
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users/12345", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

func BenchmarkPathMatchingWithWildcard(b *testing.B) {
	engine := we.New()
	engine.Handle("/api/**", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("OK"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/123/posts", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkMultipleRoutes benchmarks routing with many registered routes
func BenchmarkMultipleRoutes(b *testing.B) {
	engine := we.New()

	// Register 100 routes
	for i := 0; i < 100; i++ {
		path := "/api/endpoint" + string(rune('0'+i%10)) + string(rune('0'+i/10))
		engine.Handle(path, func(w http.ResponseWriter, r we.RequestScope) error {
			w.Write([]byte("OK"))
			return nil
		})
	}

	// Test matching a specific route
	req := httptest.NewRequest(http.MethodGet, "/api/endpoint05", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkMethodRouting benchmarks method-specific routing
func BenchmarkMethodRouting(b *testing.B) {
	engine := we.New()

	engine.HandleMethod(http.MethodGet, "/api/resource", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("GET"))
		return nil
	})
	engine.HandleMethod(http.MethodPost, "/api/resource", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("POST"))
		return nil
	})
	engine.HandleMethod(http.MethodPut, "/api/resource", func(w http.ResponseWriter, r we.RequestScope) error {
		w.Write([]byte("PUT"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}

// BenchmarkCompleteStack benchmarks a complete realistic stack
func BenchmarkCompleteStack(b *testing.B) {
	engine := we.New()

	// Session management
	sessionManager := we.DefaultSessionManager().Build()
	engine.SetSessionManager(sessionManager)

	// CORS filter
	corsFilter := filters.Cors().
		AllowedOrigins("*").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		Build()
	engine.AddFilter(corsFilter)

	// Custom logging filter
	engine.AddFilter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
		// Simulate logging
		_ = r.Request().URL.Path
		return nil
	}))

	// Authentication
	user := security.User{
		Username: "admin",
		Password: "admin123",
		Scopes:   []string{"admin"},
	}
	authProvider := security.BasicAuthenticationProvider(user).Build()
	secFilter := security.Filter(false).
		Path("/api/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		Build()
	engine.AddFilter(secFilter)

	// Handler with path variable
	engine.Handle("/api/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
		userId := r.Var("id")
		r.SetInSession("lastUserId", userId)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"` + userId + `"}`))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users/12345", nil)
	req.SetBasicAuth("admin", "admin123")
	req.Header.Set("Origin", "https://example.com")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, req)
	}
}
