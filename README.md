# go-we

**Go-We** (pronounced "go wheeee!") is a lightweight, feature-rich HTTP web framework for Go that provides common web application functionality out of the box. It implements the `http.Handler` interface and can be used as a drop-in replacement for `http.DefaultServeMux`, while offering significantly more features.

## Features

- **Advanced Routing** - Path variables, wildcards (`*`, `**`), and method-specific handlers
- **Session Management** - Built-in session support with configurable storage and lifecycle
- **Security & Authentication** - Comprehensive auth support (Basic, Bearer/JWT, OAuth2/OIDC, mTLS, Form-based)
- **Authorization** - Flexible path-based and scope-based authorization rules
- **Filter Chain** - Middleware-style filter architecture for cross-cutting concerns
- **CORS Support** - Built-in CORS filter with path-specific configuration
- **Security Headers** - Response headers filter with secure defaults (HSTS, CSP, etc.)
- **Event-Driven Errors** - Elegant error handling with flow control events
- **Graceful Shutdown** - Built-in graceful shutdown with configurable timeout
- **Request Scope** - Enhanced request context with easy access to variables, parameters, and session
- **Testing Utilities** - Built-in mocking and testing helpers

## Installation

```bash
go get github.com/gomatbase/go-we
```

**Requirements:** Go 1.24.0 or higher

## Quick Start

### Basic Server

```go
package main

import (
    "net/http"
    "github.com/gomatbase/go-we"
)

func main() {
    engine := we.New()
    
    engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
        w.Write([]byte("Hello, World!"))
        return nil
    })
    
    engine.Listen(":8080")
}
```

### Path Variables

```go
engine.Handle("/users/{id}/posts/{postId}", func(w http.ResponseWriter, scope we.RequestScope) error {
    userId := scope.Var("id")
    postId := scope.Var("postId")
    w.Write([]byte("User: " + userId + ", Post: " + postId))
    return nil
})
```

### Method-Specific Handlers

```go
engine.HandleMethod("GET", "/api/users", listUsers)
engine.HandleMethod("POST", "/api/users", createUser)
engine.HandleMethod("PUT", "/api/users/{id}", updateUser)
engine.HandleMethod("DELETE", "/api/users/{id}", deleteUser)
```

### With Sessions

```go
import "time"

engine := we.New()

// Configure session manager
engine.SetSessionManager(we.DefaultSessionManager(we.SessionManagerConfiguration{
    SessionTimeout: time.Hour,
    CookieName: "myapp_session",
}))

engine.Handle("/login", func(w http.ResponseWriter, scope we.RequestScope) error {
    scope.SetInSession("user_id", "12345")
    w.Write([]byte("Logged in!"))
    return nil
})

engine.Handle("/profile", func(w http.ResponseWriter, scope we.RequestScope) error {
    userId := scope.GetFromSession("user_id")
    if userId == nil {
        return events.UnauthorizedError
    }
    w.Write([]byte("User ID: " + userId.(string)))
    return nil
})
```

## Core Concepts

### RequestScope

The `RequestScope` interface wraps `http.Request` and provides convenient access to request data:

```go
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    // Path variables
    id := scope.Var("id")
    name, found := scope.LookupVar("name")
    
    // Query parameters
    page := scope.Parameter("page")
    tags := scope.Parameters("tag") // multiple values
    
    // Request attributes (shared between filters and handlers)
    scope.Set("request_id", generateId())
    requestId := scope.Get("request_id")
    
    // Session attributes
    scope.SetInSession("last_visit", time.Now())
    lastVisit := scope.GetFromSession("last_visit")
    
    // Access underlying request
    method := scope.Request().Method
    ctx := scope.Context() // for cancellation/timeouts
    
    return nil
}
```

### Error Handling with Events

Return `WeEvent` errors to control response flow:

```go
import "github.com/gomatbase/go-we/events"

func handler(w http.ResponseWriter, scope we.RequestScope) error {
    // Standard HTTP errors
    if unauthorized {
        return events.UnauthorizedError
    }
    
    if notFound {
        return events.NotFoundError
    }
    
    // With custom payload
    if badInput {
        return events.BadRequestError.WithPayload(
            "application/json",
            []byte(`{"error": "Invalid input"}`),
        )
    }
    
    // Redirects
    if needsLogin {
        return events.FoundRedirect.WithAttribute("/login")
    }
    
    // Custom status
    return events.New(418, "I'm a teapot")
}
```

### Filters

Filters execute before handlers and can modify requests/responses or control flow:

```go
func loggingFilter(headers http.Header, scope we.RequestScope) error {
    start := time.Now()
    
    // Add custom header
    headers.Set("X-Request-ID", generateId())
    
    // Store data for handler
    scope.Set("start_time", start)
    
    // Continue to next filter/handler
    return nil
}

engine.AddFilter(we.FilterFunction(loggingFilter))
```

### Built-in CORS Filter

```go
import "github.com/gomatbase/go-we/filters"

corsFilter := filters.Cors().
    AllowedOrigins("https://example.com", "https://app.example.com").
    AllowedMethods("GET", "POST", "PUT", "DELETE").
    AllowedHeaders("Authorization", "Content-Type").
    AllowCredentials().
    MaxAge(3600).
    Build()

engine.AddFilter(corsFilter)
```

### Built-in Security Headers Filter

```go
import "github.com/gomatbase/go-we/filters"

headersFilter := filters.ResponseHeaders().
    HSTS(31536000, true, false). // max-age=1 year, includeSubDomains, no preload
    CSP("default-src 'self'; script-src 'self' 'unsafe-inline'").
    ReferrerPolicy(filters.ReferrerStrictOriginWhenCrossOrigin).
    Build()

engine.AddFilter(headersFilter)
```

## Authentication & Authorization

### Basic Authentication

```go
import "github.com/gomatbase/go-we/security"

securityFilter := security.Filter(true). // restricted by default
    Path("/admin/**").
        Authentication(
            security.BasicAuthenticationProvider(
                security.User{Username: "admin", Password: "secret", Scopes: []string{"admin"}},
            ).Build(),
        ).
        Authorize(security.Scope("admin")).
    Build()

engine.AddFilter(securityFilter)
```

### Bearer Token (JWT) Authentication

```go
import "github.com/gomatbase/go-we/security"

// Implement TokenIntrospector interface
type MyTokenIntrospector struct{}

func (m *MyTokenIntrospector) Introspect(ctx context.Context, token string) (*security.User, error) {
    // Validate JWT and return user
    // ...
    return &security.User{Username: "john", Scopes: []string{"api:read"}}, nil
}

securityFilter := security.Filter(false). // anonymous by default
    Path("/api/**").
        Authentication(
            security.BearerAuthenticationProvider().
                Introspector(&MyTokenIntrospector{}).
                Build(),
        ).
        Authorize(security.Scope("api:read")).
    Build()

engine.AddFilter(securityFilter)
```

### OAuth2/OpenID Connect

```go
import "github.com/gomatbase/go-we/security"

// Configure OpenID provider
oidcProvider := security.OpenIdIdentityProvider().
    Issuer("https://accounts.google.com").
    ClientId("your-client-id").
    ClientSecret("your-client-secret").
    RedirectHandler("/auth/callback").
    Scopes("openid", "profile", "email").
    Build()

securityFilter := security.Filter(true).
    Path("/app/**").
        Authentication(
            security.SSOAuthenticationProvider(oidcProvider).
                LoginPath("/login").
                Build(),
        ).
    Build()

engine.SetSessionManager(we.DefaultSessionManager(we.SessionManagerConfiguration{}))
engine.AddFilter(securityFilter)
```

### Form-Based Login

```go
import "github.com/gomatbase/go-we/security"

loginForm := security.DefaultLoginForm(security.LoginFormConfiguration{
    Action: "/login",
    Title: "Please Login",
})

securityFilter := security.Filter(true).
    Path("/app/**").
        Authentication(
            security.LoginFormAuthenticationProvider(
                security.User{Username: "user", Password: "pass"},
            ).
                LoginForm(loginForm).
                Required(true).
                RedirectToForm(true).
                Build(),
        ).
    Build()

engine.SetSessionManager(we.DefaultSessionManager(we.SessionManagerConfiguration{}))
engine.AddFilter(securityFilter)
```

### Multiple Authentication Methods

```go
securityFilter := security.Filter(false). // anonymous by default
    // Root-level bearer auth
    Authentication(
        security.BearerAuthenticationProvider().
            Introspector(myIntrospector).
            Build(),
    ).
    
    // Public endpoints
    Path("/api/public/**").
        Anonymous().
    
    // API requires token
    Path("/api/v1/**").
        Authorize(security.Scope("api:read")).
    
    // Admin requires admin scope
    Path("/api/admin/**").
        Authorize(security.Scope("admin")).
    
    // Login form for web interface
    Path("/app/**").
        Authentication(
            security.LoginFormAuthenticationProvider(users...).Build(),
        ).
    
    Build()
```

## Graceful Shutdown

```go
var shutdown func(time.Duration) error

engine := we.New()
engine.HookGraciousShutdownFunction(&shutdown)

// Configure handlers...

go engine.Listen(":8080")

// On shutdown signal...
if err := shutdown(30 * time.Second); err != nil {
    log.Printf("Shutdown error: %v", err)
}
```

## Path Matching

### Precedence Rules

When multiple patterns match a path, go-we uses this precedence order:

1. **Exact paths** - `/users/123` 
2. **Path variables** - `/users/{id}`
3. **Single wildcard** - `/users/*`
4. **Double wildcard** - `/users/**`

### Wildcard Examples

```go
// Single wildcard - matches one path segment
engine.Handle("/api/*", handler)        // Matches: /api/users, /api/posts
                                        // Not: /api/users/123

// Double wildcard - matches any remaining path
engine.Handle("/api/**", handler)       // Matches: /api/users, /api/users/123, /api/users/123/posts

// Root path wildcard
engine.Handle("/**", handler)           // Matches: /, /any, /any/path
```

## Testing

go-we provides testing utilities:

```go
import "github.com/gomatbase/go-we/test"

func TestMyHandler(t *testing.T) {
    // Create mocked request scope
    scope := test.NewRequestScopeMocker(t).
        Var("id", "123").
        Parameter("page", "1").
        SessionAttribute("user_id", "456").
        Build()
    
    w := httptest.NewRecorder()
    err := myHandler(w, scope)
    
    if err != nil {
        t.Errorf("Handler returned error: %v", err)
    }
}
```

## Links

- **Documentation**: [pkg.go.dev/github.com/gomatbase/go-we](https://pkg.go.dev/github.com/gomatbase/go-we)
- **Source Code**: [github.com/gomatbase/go-we](https://github.com/gomatbase/go-we)
- **Issues**: [github.com/gomatbase/go-we/issues](https://github.com/gomatbase/go-we/issues)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - Copyright (c) 2020-2026 GOM

See [LICENSE](LICENSE) file for details.
