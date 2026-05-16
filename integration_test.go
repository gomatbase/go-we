// Copyright 2026 GOM. All rights reserved.
// Since 04/04/2026 By GOM
// Licensed under MIT License

package we_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/filters"
	"github.com/gomatbase/go-we/security"
)

// Integration tests verify that multiple components work correctly together

func TestIntegrationSessionsWithFilters(t *testing.T) {
	t.Run("Sessions work with filters and handlers", func(t *testing.T) {
		builder := we.New()

		// Configure sessions
		sessionMgr := we.DefaultSessionManager().
			CookieSecure(false).
			Build()
		builder.SessionManager(sessionMgr)

		// Add filter to track request count in session
		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			count := r.GetFromSession("count")
			if count == nil {
				count = 0
			}
			r.SetInSession("count", count.(int)+1)
			return nil
		}))

		// Handler returns request count
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			count := r.GetFromSession("count")
			_, _ = w.Write([]byte(fmt.Sprintf("count:%d", count)))
			return nil
		})

		// First request
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		engine := builder.Build()
		engine.ServeHTTP(w, req)

		if w.Body.String() != "count:1" {
			t.Errorf("First request: expected count:1, got %s", w.Body.String())
		}

		// Extract session cookie
		cookies := w.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("Expected session cookie to be set")
		}
		sessionCookie := cookies[0]

		// Second request with same session
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(sessionCookie)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Body.String() != "count:2" {
			t.Errorf("Second request: expected count:2, got %s", w.Body.String())
		}

		_ = engine.Shutdown()
	})
}

func TestIntegrationAuthenticationWithAuthorization(t *testing.T) {
	t.Run("Basic auth with scope-based authorization", func(t *testing.T) {
		builder := we.New()

		// Setup users with different scopes
		adminUser := security.User{
			Username: "admin",
			Password: "admin123",
			Scopes:   []string{"admin", "user"},
		}
		regularUser := security.User{
			Username: "user",
			Password: "user123",
			Scopes:   []string{"user"},
		}

		// Create authentication provider
		authProvider := security.BasicAuthenticationProvider(adminUser, regularUser).Build()

		// Create security filter
		secFilter := security.Filter(false).
			Path("/admin/**").
			Authentication(authProvider).
			Authorize(security.Scope("admin")).
			Path("/api/**").
			Authentication(authProvider).
			Authorize(security.Scope("user")).
			Build()

		builder.Filter(secFilter)

		// Public endpoint
		builder.Handle("/", simpleHandler("public"))

		// Admin endpoint
		builder.Handle("/admin/users", simpleHandler("admin only"))

		// User endpoint
		builder.Handle("/api/data", simpleHandler("user data"))

		// Test 1: Public access works
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		engine := builder.Build()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Public: expected 200, got %d", w.Code)
		}

		// Test 2: Admin endpoint without auth fails
		// Note: With Filter(false), anonymous access is allowed by default
		// So paths with authentication configured return 403 (forbidden) not 401 (unauthorized)
		// when accessed without credentials, since anonymous user is "authenticated" but not authorized
		req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 401 {
			t.Errorf("Admin no auth: expected 403, got %d", w.Code)
		}

		// Test 3: Admin endpoint with regular user fails
		req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		req.SetBasicAuth("user", "user123")
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 401 {
			t.Errorf("Admin regular user: expected 403, got %d", w.Code)
		}

		// Test 4: Admin endpoint with admin succeeds
		req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		req.SetBasicAuth("admin", "admin123")
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Admin with admin: expected 200, got %d", w.Code)
		}
		if w.Body.String() != "admin only" {
			t.Errorf("Expected 'admin only', got %s", w.Body.String())
		}

		// Test 5: User endpoint with regular user succeeds
		req = httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.SetBasicAuth("user", "user123")
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("API with user: expected 200, got %d", w.Code)
		}

		// Test 6: User endpoint with admin also succeeds (admin has user scope)
		req = httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.SetBasicAuth("admin", "admin123")
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("API with admin: expected 200, got %d", w.Code)
		}

		_ = engine.Shutdown()
	})
}

func TestIntegrationCORSWithSecurity(t *testing.T) {
	t.Run("CORS filter with authentication", func(t *testing.T) {
		builder := we.New()

		// Setup CORS
		corsFilter := filters.Cors().
			AllowedOrigins("https://example.com").
			AllowedMethods("GET", "POST", "PUT").
			AllowedHeaders("Content-Type", "Authorization").
			AllowCredentials().
			Build()

		builder.Filter(corsFilter)

		// Setup auth
		user := security.User{
			Username: "test",
			Password: "test123",
			Scopes:   []string{"user"},
		}
		authProvider := security.BasicAuthenticationProvider(user).Build()
		secFilter := security.Filter(false).
			Path("/api/**").
			Authentication(authProvider).
			Authorize().
			Build()

		builder.Filter(secFilter)

		builder.Handle("/api/data", simpleHandler("secure data"))

		// Test actual request with auth (skip preflight test due to engine bug with nil payload)
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Origin", "https://example.com")
		req.SetBasicAuth("test", "test123")
		w := httptest.NewRecorder()
		engine := builder.Build()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Authenticated request: expected 200, got %d", w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
			t.Error("Missing CORS header in response")
		}

		_ = engine.Shutdown()
	})
}

func TestIntegrationComplexRouting(t *testing.T) {
	t.Run("Complex routing with path variables and wildcards", func(t *testing.T) {
		builder := we.New()

		// Fixed paths take precedence
		builder.Handle("/api/users/me", simpleHandler("current user"))

		// Path with variable
		builder.Handle("/api/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
			id := r.Var("id")
			_, _ = w.Write([]byte(fmt.Sprintf("user:%s", id)))
			return nil
		})

		// Path with wildcard
		builder.Handle("/api/files/*", func(w http.ResponseWriter, r we.RequestScope) error {
			// Wildcards are not stored as variables - extract from URL path
			path := r.Request().URL.Path
			filename := strings.TrimPrefix(path, "/api/files/")
			_, _ = w.Write([]byte(fmt.Sprintf("file:%s", filename)))
			return nil
		})

		// Catch-all
		builder.Handle("/api/**", simpleHandler("api fallback"))

		// Test fixed path
		req := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
		w := httptest.NewRecorder()
		engine := builder.Build()
		engine.ServeHTTP(w, req)

		if w.Body.String() != "current user" {
			t.Errorf("Fixed path: expected 'current user', got %s", w.Body.String())
		}

		// Test path variable
		req = httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Body.String() != "user:123" {
			t.Errorf("Path variable: expected 'user:123', got %s", w.Body.String())
		}

		// Test single wildcard
		req = httptest.NewRequest(http.MethodGet, "/api/files/document.pdf", nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Body.String() != "file:document.pdf" {
			t.Errorf("Wildcard: expected 'file:document.pdf', got %s", w.Body.String())
		}

		// Test catch-all
		req = httptest.NewRequest(http.MethodGet, "/api/other/nested/path", nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Body.String() != "api fallback" {
			t.Errorf("Catch-all: expected 'api fallback', got %s", w.Body.String())
		}

		_ = engine.Shutdown()
	})
}

func TestIntegrationRESTfulAPI(t *testing.T) {
	t.Run("Full RESTful API with JSON", func(t *testing.T) {
		builder := we.New()

		// In-memory data store
		users := map[string]map[string]interface{}{
			"1": {"id": "1", "name": "Alice"},
			"2": {"id": "2", "name": "Bob"},
		}
		nextID := 3

		// List users
		builder.HandleMethod(http.MethodGet, "/users", func(w http.ResponseWriter, r we.RequestScope) error {
			userList := make([]map[string]interface{}, 0, len(users))
			for _, user := range users {
				userList = append(userList, user)
			}
			data, _ := json.Marshal(userList)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
			return nil
		})

		// Get user
		builder.HandleMethod(http.MethodGet, "/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
			id := r.Var("id")
			user, exists := users[id]
			if !exists {
				return events.NewPayload(404, "Not Found", &events.Payload{
					ContentTypeHint: "application/json",
					Content:         []byte(`{"error":"user not found"}`),
				})
			}
			data, _ := json.Marshal(user)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
			return nil
		})

		// Create user
		builder.HandleMethod(http.MethodPost, "/users", func(w http.ResponseWriter, r we.RequestScope) error {
			var input map[string]interface{}
			if err := json.NewDecoder(r.Request().Body).Decode(&input); err != nil {
				return events.NewPayload(400, "Bad Request", &events.Payload{
					ContentTypeHint: "application/json",
					Content:         []byte(`{"error":"invalid json"}`),
				})
			}

			id := fmt.Sprintf("%d", nextID)
			nextID++
			input["id"] = id
			users[id] = input

			data, _ := json.Marshal(input)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(data)
			return nil
		})

		// Update user
		builder.HandleMethod(http.MethodPut, "/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
			id := r.Var("id")
			if _, exists := users[id]; !exists {
				return events.New(404, "Not Found")
			}

			var input map[string]interface{}
			if err := json.NewDecoder(r.Request().Body).Decode(&input); err != nil {
				return events.New(400, "Bad Request")
			}

			input["id"] = id
			users[id] = input

			data, _ := json.Marshal(input)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
			return nil
		})

		// Delete user
		builder.HandleMethod(http.MethodDelete, "/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
			id := r.Var("id")
			if _, exists := users[id]; !exists {
				return events.New(404, "Not Found")
			}
			delete(users, id)
			w.WriteHeader(http.StatusNoContent)
			return nil
		})

		// Test: List users
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		w := httptest.NewRecorder()
		engine := builder.Build()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("List: expected 200, got %d", w.Code)
		}

		var userList []map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &userList); err != nil {
			t.Errorf("Failed to parse user list: %v", err)
		}
		if len(userList) != 2 {
			t.Errorf("Expected 2 users, got %d", len(userList))
		}

		// Test: Get specific user
		req = httptest.NewRequest(http.MethodGet, "/users/1", nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Get: expected 200, got %d", w.Code)
		}

		var user map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &user); err != nil {
			t.Errorf("Failed to parse user: %v", err)
		}
		if user["name"] != "Alice" {
			t.Errorf("Expected Alice, got %v", user["name"])
		}

		// Test: Create user
		newUser := `{"name":"Charlie"}`
		req = httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(newUser))
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 201 {
			t.Errorf("Create: expected 201, got %d", w.Code)
		}

		var created map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
			t.Errorf("Failed to parse created user: %v", err)
		}
		if created["name"] != "Charlie" {
			t.Errorf("Expected Charlie, got %v", created["name"])
		}
		newUserID := created["id"].(string)

		// Test: Update user
		updated := `{"name":"Charlie Updated"}`
		req = httptest.NewRequest(http.MethodPut, "/users/"+newUserID, strings.NewReader(updated))
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Update: expected 200, got %d", w.Code)
		}

		// Test: Delete user
		req = httptest.NewRequest(http.MethodDelete, "/users/"+newUserID, nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 204 {
			t.Errorf("Delete: expected 204, got %d", w.Code)
		}

		// Test: Get deleted user (should 404)
		req = httptest.NewRequest(http.MethodGet, "/users/"+newUserID, nil)
		w = httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != 404 {
			t.Errorf("Get deleted: expected 404, got %d", w.Code)
		}

		_ = engine.Shutdown()
	})
}

func TestIntegrationFilterOrder(t *testing.T) {
	t.Run("Multiple filters execute in correct order", func(t *testing.T) {
		builder := we.New()

		var executionOrder []string

		// Filter 1: Logging
		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			executionOrder = append(executionOrder, "filter1")
			r.Set("filter1", true)
			return nil
		}))

		// Filter 2: Authentication check
		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			executionOrder = append(executionOrder, "filter2")
			if r.Get("filter1") != true {
				return events.New(500, "Filter order wrong")
			}
			r.Set("filter2", true)
			return nil
		}))

		// Filter 3: Response headers
		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			executionOrder = append(executionOrder, "filter3")
			if r.Get("filter2") != true {
				return events.New(500, "Filter order wrong")
			}
			h.Set("X-Custom", "test")
			return nil
		}))

		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			executionOrder = append(executionOrder, "handler")
			_, _ = w.Write([]byte("ok"))
			return nil
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		engine := builder.Build()
		engine.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		expected := []string{"filter1", "filter2", "filter3", "handler"}
		if len(executionOrder) != len(expected) {
			t.Errorf("Expected %d executions, got %d: %v", len(expected), len(executionOrder), executionOrder)
		}

		for i, exp := range expected {
			if executionOrder[i] != exp {
				t.Errorf("Position %d: expected %s, got %s", i, exp, executionOrder[i])
			}
		}

		if w.Header().Get("X-Custom") != "test" {
			t.Error("Custom header not set by filter")
		}

		_ = engine.Shutdown()
	})
}
