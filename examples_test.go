// Copyright 2025-2026 GOM. All rights reserved.
// Since 14/01/2025 By GOM
// Licensed under MIT License

package we_test

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/filters"
	"github.com/gomatbase/go-we/security"
)

// Example_basicHandler demonstrates creating a basic HTTP handler.
func Example_basicHandler() {
	builder := we.New()

	builder.Handle("/hello", func(w http.ResponseWriter, r we.RequestScope) error {
		_, _ = fmt.Fprintln(w, "Hello, World!")
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_pathVariables demonstrates extracting path variables from routes.
func Example_pathVariables() {
	builder := we.New()

	builder.Handle("/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
		userID := r.Var("id")
		_, _ = fmt.Fprintf(w, "User ID: %s", userID)
		return nil
	})

	builder.Handle("/posts/{postId}/comments/{commentId}", func(w http.ResponseWriter, r we.RequestScope) error {
		postID := r.Var("postId")
		commentID := r.Var("commentId")
		_, _ = fmt.Fprintf(w, "Post: %s, Comment: %s", postID, commentID)
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_queryParameters demonstrates handling query parameters.
func Example_queryParameters() {
	builder := we.New()

	builder.Handle("/search", func(w http.ResponseWriter, r we.RequestScope) error {
		searchTerm := r.Parameter("q")
		page := r.Parameter("page")
		_, _ = fmt.Fprintf(w, "Search: %s, Page: %s", searchTerm, page)
		return nil
	})

	// Request: GET /search?q=golang&page=1
	// Start server: builder.Build().Listen(":8080")
}

// Example_methodRouting demonstrates HTTP method-specific routing.
func Example_methodRouting() {
	builder := we.New()

	// Same path, different methods
	builder.Handle("/resource", func(w http.ResponseWriter, r we.RequestScope) error {
		switch r.Request().Method {
		case http.MethodGet:
			_, _ = fmt.Fprintln(w, "GET request")
		case http.MethodPost:
			_, _ = fmt.Fprintln(w, "POST request")
		case http.MethodPut:
			_, _ = fmt.Fprintln(w, "PUT request")
		case http.MethodDelete:
			_, _ = fmt.Fprintln(w, "DELETE request")
		}
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_filters demonstrates using filters for cross-cutting concerns.
func Example_filters() {
	builder := we.New()

	// Logging filter
	loggingFilter := we.FilterFunction(func(h http.Header, r we.RequestScope) error {
		fmt.Printf("Request: %s %s\n", r.Request().Method, r.Request().URL.Path)
		return nil
	})

	builder.Filter(loggingFilter)

	builder.Handle("/api/users", func(w http.ResponseWriter, r we.RequestScope) error {
		_, _ = fmt.Fprintln(w, "User list")
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_sessions demonstrates session management.
func Example_sessions() {
	builder := we.New()

	// Configure session manager
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).
		CookieName("session_id").
		Build()
	builder.SessionManager(sessionManager)

	builder.Handle("/login", func(w http.ResponseWriter, r we.RequestScope) error {
		r.Session().Set("username", "john")
		r.Session().Set("role", "admin")
		_, _ = fmt.Fprintln(w, "Logged in")
		return nil
	})

	builder.Handle("/profile", func(w http.ResponseWriter, r we.RequestScope) error {
		username := r.Session().Get("username")
		role := r.Session().Get("role")
		_, _ = fmt.Fprintf(w, "User: %v, Role: %v", username, role)
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_cors demonstrates CORS configuration.
func Example_cors() {
	builder := we.New()

	corsFilter := filters.Cors().
		AllowedOrigins("https://example.com", "https://app.example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowedHeaders("Content-Type", "Authorization").
		AllowCredentials().
		MaxAge(3600).
		Build()

	builder.Filter(corsFilter)

	builder.Handle("/api/data", func(w http.ResponseWriter, r we.RequestScope) error {
		_, _ = fmt.Fprintln(w, "Data with CORS enabled")
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_basicAuthentication demonstrates basic authentication.
func Example_basicAuthentication() {
	builder := we.New()

	// Create users
	adminUser := security.User{
		Username: "admin",
		Password: "secret",
		Scopes:   []string{"admin"},
	}

	// Create authentication provider
	authProvider := security.BasicAuthenticationProvider(adminUser).Build()

	// Configure security filter
	secFilter := security.Filter(false).
		Path("/admin/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		Build()

	builder.Filter(secFilter)

	builder.Handle("/admin/dashboard", func(w http.ResponseWriter, r we.RequestScope) error {
		user := r.Get(security.UserAttributeName).(*security.User)
		_, _ = fmt.Fprintf(w, "Welcome, %s!", user.Username)
		return nil
	})

	// Request with Authorization: Basic YWRtaW46c2VjcmV0
	// Start server: builder.Build().Listen(":8080")
}

// Example_errorHandling demonstrates error handling with WeEvents.
func Example_errorHandling() {
	builder := we.New()

	builder.Handle("/error", func(w http.ResponseWriter, r we.RequestScope) error {
		// Return error with status code
		return events.New(http.StatusBadRequest, "Invalid request")
	})

	builder.Handle("/custom-error", func(w http.ResponseWriter, r we.RequestScope) error {
		// Return custom error
		return fmt.Errorf("something went wrong")
	})

	// Errors with payloads
	builder.Handle("/json-error", func(w http.ResponseWriter, r we.RequestScope) error {
		payload := &events.Payload{
			ContentTypeHint: "application/json",
			Content:         []byte(`{"error":"Resource not found"}`),
		}
		return events.NewPayload(http.StatusNotFound, "Not Found", payload)
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_attributes demonstrates using request attributes for passing data.
func Example_attributes() {
	builder := we.New()

	// Filter that sets an attribute
	authFilter := we.FilterFunction(func(h http.Header, r we.RequestScope) error {
		r.Set("user-id", "12345")
		r.Set("request-time", time.Now())
		return nil
	})

	builder.Filter(authFilter)

	builder.Handle("/data", func(w http.ResponseWriter, r we.RequestScope) error {
		userID := r.Get("user-id").(string)
		requestTime := r.Get("request-time").(time.Time)
		_, _ = fmt.Fprintf(w, "User: %s, Time: %s", userID, requestTime.Format(time.RFC3339))
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_wildcardRoutes demonstrates wildcard routing patterns.
func Example_wildcardRoutes() {
	builder := we.New()

	// Single wildcard - matches one path segment
	builder.Handle("/files/*", func(w http.ResponseWriter, r we.RequestScope) error {
		// Extract the wildcard portion from the URL path
		path := r.Request().URL.Path
		file := path[len("/files/"):]
		_, _ = fmt.Fprintf(w, "File: %s", file)
		return nil
	})

	// Double wildcard - matches multiple path segments
	builder.Handle("/static/**", func(w http.ResponseWriter, r we.RequestScope) error {
		// Extract the full path after "/static/"
		path := r.Request().URL.Path
		resource := path[len("/static/"):]
		_, _ = fmt.Fprintf(w, "Static resource: %s", resource)
		return nil
	})

	// Request: GET /files/document.pdf -> File: document.pdf
	// Request: GET /static/css/main.css -> Static resource: css/main.css
	// Start server: builder.Build().Listen(":8080")
}

// Example_shutdown demonstrates graceful shutdown.
func Example_shutdown() {
	builder := we.New()

	builder.Handle("/hello", func(w http.ResponseWriter, r we.RequestScope) error {
		_, _ = fmt.Fprintln(w, "Hello!")
		return nil
	})

	// Start server in a goroutine
	engine := builder.Build()
	go func() {
		if err := engine.Listen(":8080"); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	// Wait for shutdown signal...
	// engine.Shutdown()
}

// Example_restfulAPI demonstrates a complete RESTful API.
func Example_restfulAPI() {
	builder := we.New()

	// List all users
	builder.Handle("/users", func(w http.ResponseWriter, r we.RequestScope) error {
		if r.Request().Method == http.MethodGet {
			_, _ = fmt.Fprintln(w, `[{"id":"1","name":"John"},{"id":"2","name":"Jane"}]`)
		} else if r.Request().Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintln(w, `{"id":"3","name":"New User"}`)
		}
		return nil
	})

	// Get/Update/Delete single user
	builder.Handle("/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
		id := r.Var("id")
		switch r.Request().Method {
		case http.MethodGet:
			_, _ = fmt.Fprintf(w, `{"id":"%s","name":"John"}`, id)
		case http.MethodPut:
			_, _ = fmt.Fprintf(w, `{"id":"%s","name":"Updated User"}`, id)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}

// Example_completeApplication demonstrates a complete application setup.
func Example_completeApplication() {
	builder := we.New()

	// Configure session manager
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).
		CookieName("app_session").
		Build()
	builder.SessionManager(sessionManager)

	// Configure CORS
	corsFilter := filters.Cors().
		AllowedOrigins("https://app.example.com").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowedHeaders("Content-Type", "Authorization").
		AllowCredentials().
		Build()
	builder.Filter(corsFilter)

	// Configure authentication
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

	authProvider := security.BasicAuthenticationProvider(adminUser, regularUser).Build()

	secFilter := security.Filter(false).
		Path("/api/**").
		Authentication(authProvider).
		Authorize(security.Scope("user")).
		Path("/admin/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		Build()
	builder.Filter(secFilter)

	// Public endpoints
	builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
		_, _ = fmt.Fprintln(w, "Welcome!")
		return nil
	})

	// Protected API endpoints
	builder.Handle("/api/profile", func(w http.ResponseWriter, r we.RequestScope) error {
		user := r.Get(security.UserAttributeName).(*security.User)
		_, _ = fmt.Fprintf(w, `{"username":"%s"}`, user.Username)
		return nil
	})

	// Admin endpoints
	builder.Handle("/admin/dashboard", func(w http.ResponseWriter, r we.RequestScope) error {
		_, _ = fmt.Fprintln(w, "Admin Dashboard")
		return nil
	})

	// Start server: builder.Build().Listen(":8080")
}
