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
    engine := we.New()

    engine.Handle("/hello", func(w http.ResponseWriter, r we.RequestScope) error {
        fmt.Fprintln(w, "Hello, World!")
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_pathVariables demonstrates extracting path variables from routes.
func Example_pathVariables() {
    engine := we.New()

    engine.Handle("/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
        userID := r.Var("id")
        fmt.Fprintf(w, "User ID: %s", userID)
        return nil
    })

    engine.Handle("/posts/{postId}/comments/{commentId}", func(w http.ResponseWriter, r we.RequestScope) error {
        postID := r.Var("postId")
        commentID := r.Var("commentId")
        fmt.Fprintf(w, "Post: %s, Comment: %s", postID, commentID)
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_queryParameters demonstrates handling query parameters.
func Example_queryParameters() {
    engine := we.New()

    engine.Handle("/search", func(w http.ResponseWriter, r we.RequestScope) error {
        searchTerm := r.Parameter("q")
        page := r.Parameter("page")
        fmt.Fprintf(w, "Search: %s, Page: %s", searchTerm, page)
        return nil
    })

    // Request: GET /search?q=golang&page=1
    // Start server: engine.Listen(":8080")
}

// Example_methodRouting demonstrates HTTP method-specific routing.
func Example_methodRouting() {
    engine := we.New()

    // Same path, different methods
    engine.Handle("/resource", func(w http.ResponseWriter, r we.RequestScope) error {
        switch r.Request().Method {
        case http.MethodGet:
            fmt.Fprintln(w, "GET request")
        case http.MethodPost:
            fmt.Fprintln(w, "POST request")
        case http.MethodPut:
            fmt.Fprintln(w, "PUT request")
        case http.MethodDelete:
            fmt.Fprintln(w, "DELETE request")
        }
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_filters demonstrates using filters for cross-cutting concerns.
func Example_filters() {
    engine := we.New()

    // Logging filter
    loggingFilter := we.FilterFunction(func(h http.Header, r we.RequestScope) error {
        fmt.Printf("Request: %s %s\n", r.Request().Method, r.Request().URL.Path)
        return nil
    })

    engine.AddFilter(loggingFilter)

    engine.Handle("/api/users", func(w http.ResponseWriter, r we.RequestScope) error {
        fmt.Fprintln(w, "User list")
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_sessions demonstrates session management.
func Example_sessions() {
    engine := we.New()

    // Configure session manager
    sessionManager := we.DefaultSessionManager().
        SessionTimeout(30 * time.Minute).
        CookieName("session_id").
        Build()
    engine.SetSessionManager(sessionManager)

    engine.Handle("/login", func(w http.ResponseWriter, r we.RequestScope) error {
        r.SetInSession("username", "john")
        r.SetInSession("role", "admin")
        fmt.Fprintln(w, "Logged in")
        return nil
    })

    engine.Handle("/profile", func(w http.ResponseWriter, r we.RequestScope) error {
        username := r.GetFromSession("username")
        role := r.GetFromSession("role")
        fmt.Fprintf(w, "User: %v, Role: %v", username, role)
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_cors demonstrates CORS configuration.
func Example_cors() {
    engine := we.New()

    corsFilter := filters.Cors().
        AllowedOrigins("https://example.com", "https://app.example.com").
        AllowedMethods("GET", "POST", "PUT", "DELETE").
        AllowedHeaders("Content-Type", "Authorization").
        AllowCredentials().
        MaxAge(3600).
        Build()

    engine.AddFilter(corsFilter)

    engine.Handle("/api/data", func(w http.ResponseWriter, r we.RequestScope) error {
        fmt.Fprintln(w, "Data with CORS enabled")
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_basicAuthentication demonstrates basic authentication.
func Example_basicAuthentication() {
    engine := we.New()

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

    engine.AddFilter(secFilter)

    engine.Handle("/admin/dashboard", func(w http.ResponseWriter, r we.RequestScope) error {
        user := r.Get(security.UserAttributeName).(*security.User)
        fmt.Fprintf(w, "Welcome, %s!", user.Username)
        return nil
    })

    // Request with Authorization: Basic YWRtaW46c2VjcmV0
    // Start server: engine.Listen(":8080")
}

// Example_errorHandling demonstrates error handling with WeEvents.
func Example_errorHandling() {
    engine := we.New()

    engine.Handle("/error", func(w http.ResponseWriter, r we.RequestScope) error {
        // Return error with status code
        return events.New(http.StatusBadRequest, "Invalid request")
    })

    engine.Handle("/custom-error", func(w http.ResponseWriter, r we.RequestScope) error {
        // Return custom error
        return fmt.Errorf("something went wrong")
    })

    // Errors with payloads
    engine.Handle("/json-error", func(w http.ResponseWriter, r we.RequestScope) error {
        payload := &events.Payload{
            ContentTypeHint: "application/json",
            Content:         []byte(`{"error":"Resource not found"}`),
        }
        return events.NewPayload(http.StatusNotFound, "Not Found", payload)
    })

    // Start server: engine.Listen(":8080")
}

// Example_attributes demonstrates using request attributes for passing data.
func Example_attributes() {
    engine := we.New()

    // Filter that sets an attribute
    authFilter := we.FilterFunction(func(h http.Header, r we.RequestScope) error {
        r.Set("user-id", "12345")
        r.Set("request-time", time.Now())
        return nil
    })

    engine.AddFilter(authFilter)

    engine.Handle("/data", func(w http.ResponseWriter, r we.RequestScope) error {
        userID := r.Get("user-id").(string)
        requestTime := r.Get("request-time").(time.Time)
        fmt.Fprintf(w, "User: %s, Time: %s", userID, requestTime.Format(time.RFC3339))
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_wildcardRoutes demonstrates wildcard routing patterns.
func Example_wildcardRoutes() {
    engine := we.New()

    // Single wildcard - matches one path segment
    engine.Handle("/files/*", func(w http.ResponseWriter, r we.RequestScope) error {
        // Extract the wildcard portion from the URL path
        path := r.Request().URL.Path
        file := path[len("/files/"):]
        fmt.Fprintf(w, "File: %s", file)
        return nil
    })

    // Double wildcard - matches multiple path segments
    engine.Handle("/static/**", func(w http.ResponseWriter, r we.RequestScope) error {
        // Extract the full path after "/static/"
        path := r.Request().URL.Path
        resource := path[len("/static/"):]
        fmt.Fprintf(w, "Static resource: %s", resource)
        return nil
    })

    // Request: GET /files/document.pdf -> File: document.pdf
    // Request: GET /static/css/main.css -> Static resource: css/main.css
    // Start server: engine.Listen(":8080")
}

// Example_shutdown demonstrates graceful shutdown.
func Example_shutdown() {
    engine := we.New()

    var shutdown func() error
    engine.HookShutdownFunction(&shutdown)

    engine.Handle("/hello", func(w http.ResponseWriter, r we.RequestScope) error {
        fmt.Fprintln(w, "Hello!")
        return nil
    })

    // Start server in a goroutine
    go func() {
        if err := engine.Listen(":8080"); err != nil {
            fmt.Printf("Server error: %v\n", err)
        }
    }()

    // Wait for shutdown signal...
    // shutdown()
}

// Example_restfulAPI demonstrates a complete RESTful API.
func Example_restfulAPI() {
    engine := we.New()

    // List all users
    engine.Handle("/users", func(w http.ResponseWriter, r we.RequestScope) error {
        if r.Request().Method == http.MethodGet {
            fmt.Fprintln(w, `[{"id":"1","name":"John"},{"id":"2","name":"Jane"}]`)
        } else if r.Request().Method == http.MethodPost {
            w.WriteHeader(http.StatusCreated)
            fmt.Fprintln(w, `{"id":"3","name":"New User"}`)
        }
        return nil
    })

    // Get/Update/Delete single user
    engine.Handle("/users/{id}", func(w http.ResponseWriter, r we.RequestScope) error {
        id := r.Var("id")
        switch r.Request().Method {
        case http.MethodGet:
            fmt.Fprintf(w, `{"id":"%s","name":"John"}`, id)
        case http.MethodPut:
            fmt.Fprintf(w, `{"id":"%s","name":"Updated User"}`, id)
        case http.MethodDelete:
            w.WriteHeader(http.StatusNoContent)
        }
        return nil
    })

    // Start server: engine.Listen(":8080")
}

// Example_completeApplication demonstrates a complete application setup.
func Example_completeApplication() {
    engine := we.New()

    // Configure session manager
    sessionManager := we.DefaultSessionManager().
        SessionTimeout(30 * time.Minute).
        CookieName("app_session").
        Build()
    engine.SetSessionManager(sessionManager)

    // Configure CORS
    corsFilter := filters.Cors().
        AllowedOrigins("https://app.example.com").
        AllowedMethods("GET", "POST", "PUT", "DELETE").
        AllowedHeaders("Content-Type", "Authorization").
        AllowCredentials().
        Build()
    engine.AddFilter(corsFilter)

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
    engine.AddFilter(secFilter)

    // Public endpoints
    engine.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
        fmt.Fprintln(w, "Welcome!")
        return nil
    })

    // Protected API endpoints
    engine.Handle("/api/profile", func(w http.ResponseWriter, r we.RequestScope) error {
        user := r.Get(security.UserAttributeName).(*security.User)
        fmt.Fprintf(w, `{"username":"%s"}`, user.Username)
        return nil
    })

    // Admin endpoints
    engine.Handle("/admin/dashboard", func(w http.ResponseWriter, r we.RequestScope) error {
        fmt.Fprintln(w, "Admin Dashboard")
        return nil
    })

    // Start server: engine.Listen(":8080")
}
