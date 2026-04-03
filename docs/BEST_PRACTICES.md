# go-we Best Practices

This document outlines recommended practices for building secure, performant, and maintainable web applications with go-we.

## Table of Contents

- [Security Best Practices](#security-best-practices)
- [Error Handling Patterns](#error-handling-patterns)
- [Performance Optimization](#performance-optimization)
- [Session Management](#session-management)
- [Filter Configuration](#filter-configuration)
- [Production Deployment](#production-deployment)
- [Testing Guidelines](#testing-guidelines)

## Security Best Practices

### Authentication Configuration

#### Use Strong Authentication for Sensitive Paths

Always require authentication for sensitive endpoints and use path-specific configuration for granular control:

```go
securityFilter := security.Filter(true). // restrictedByDefault
    Authentication(bearerProvider, basicProvider).
    
    // Public endpoints
    Path("/api/public/**", "/health").
        Anonymous().
        Add().
    
    // Admin endpoints - extra authorization
    Path("/admin/**").
        Authorize(security.Scope("admin")).
        Add().
    
    Build()
```

#### Never Skip Authentication on Sensitive Operations

```go
// BAD - No authentication
engine.Handle("/api/delete-user", deleteUser)

// GOOD - Require authentication and authorization
securityFilter := security.Filter(true).
    Authentication(authProvider).
    Path("/api/delete-user").
        Authorize(security.Scope("admin")).
        Add().
    Build()
```

#### Use Realm-Based Multi-Tenancy

When supporting multiple authentication methods, use realms to isolate them:

```go
apiKeyProvider := security.BearerAuthentication().
    Realm("api").
    TokenIntrospector(apiKeyIntrospector).
    Build()

sessionProvider := security.FormAuthentication().
    Realm("web").
    CredentialsProvider(credProvider).
    Build()

// Each provider validates only its realm
security.Filter(true).
    Authentication(apiKeyProvider, sessionProvider).
    Build()
```

### CORS Security

#### Avoid Wildcard Origins in Production

```go
// BAD - Allows any origin
corsFilter := filters.Cors().
    AllowedOrigins("*").
    AllowCredentials(). // This will panic!
    Build()

// GOOD - Explicit origins
corsFilter := filters.Cors().
    AllowedOrigins(
        "https://app.example.com",
        "https://admin.example.com",
    ).
    AllowCredentials().
    Build()
```

#### Apply Principle of Least Privilege

Use path-specific CORS configuration to minimize exposure:

```go
corsFilter := filters.Cors().
    // Default: restrictive
    AllowedOrigins("https://app.example.com").
    AllowedMethods("GET", "POST").
    
    // Public API: more permissive
    Path("/api/public/**").
        AllowedOrigins("*").
        AllowedMethods("GET").
        Add().
    
    // Internal: no CORS
    Path("/internal/**", "/admin/**").
        Disabled().
        Add().
    
    Build()
```

#### Be Specific with Allowed Headers

```go
// BAD - Too permissive
AllowedHeaders("*")

// GOOD - Explicit headers only
AllowedHeaders("Content-Type", "Authorization", "X-Request-ID")
```

### Security Headers

#### Always Use HSTS in Production

```go
headersFilter := filters.ResponseHeaders().
    // Minimum 1 year for production
    HSTS(31536000, true, false).
    Build()
```

#### Implement Content Security Policy

```go
headersFilter := filters.ResponseHeaders().
    CSP("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'").
    Build()
```

#### Use Strict Frame Options for Sensitive Pages

```go
headersFilter := filters.ResponseHeaders().
    // Default: prevent embedding
    FrameOptions(filters.FrameOptionDeny).
    
    // Exception for embeddable content
    Path("/widgets/**").
        FrameOptions(filters.FrameOptionSameOrigin).
        Add().
    
    Build()
```

### Input Validation

#### Always Validate User Input

```go
func createUser(w http.ResponseWriter, scope we.RequestScope) error {
    var req CreateUserRequest
    if err := util.ReadJsonBody(scope.Request(), &req); err != nil {
        return events.BadRequestError.WithPayload(
            "application/json",
            []byte(`{"error":"invalid request body"}`),
        )
    }
    
    // Validate required fields
    if req.Email == "" || req.Username == "" {
        return events.BadRequestError.WithPayload(
            "application/json",
            []byte(`{"error":"email and username required"}`),
        )
    }
    
    // Validate format
    if !isValidEmail(req.Email) {
        return events.BadRequestError.WithPayload(
            "application/json",
            []byte(`{"error":"invalid email format"}`),
        )
    }
    
    // Proceed with creation
    // ...
}
```

#### Sanitize Path Variables

```go
func getFile(w http.ResponseWriter, scope we.RequestScope) error {
    filename := scope.Var("filename")
    
    // BAD - Path traversal vulnerability
    // content, _ := os.ReadFile("/uploads/" + filename)
    
    // GOOD - Validate and sanitize
    if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
        return events.BadRequestError
    }
    
    safePath := filepath.Join("/uploads", filepath.Clean(filename))
    if !strings.HasPrefix(safePath, "/uploads/") {
        return events.ForbiddenError
    }
    
    content, err := os.ReadFile(safePath)
    // ...
}
```

### Sensitive Data Handling

#### Never Log Sensitive Information

```go
// BAD - Logs password
log.Printf("User login attempt: %s with password %s", username, password)

// GOOD - Log only non-sensitive info
log.Printf("User login attempt: %s", username)
```

#### Don't Store Sensitive Data in Sessions

```go
// BAD - Storing password in session
scope.SetInSession("password", password)

// GOOD - Store only user identifier
scope.SetInSession("user_id", userID)
```

#### Use Secure Random for Tokens

```go
import "crypto/rand"

// GOOD - Cryptographically secure random
func generateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

## Error Handling Patterns

### Use Event-Driven Error Handling

#### Return WeEvents for Flow Control

```go
func getUser(w http.ResponseWriter, scope we.RequestScope) error {
    userId := scope.Var("id")
    
    user, err := userRepository.FindById(userId)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            // Return semantic event
            return events.NotFoundError
        }
        // Unexpected error
        return events.InternalServerError
    }
    
    return util.ReplyJson(w, user)
}
```

#### Use Custom Payloads for API Responses

```go
func createUser(w http.ResponseWriter, scope we.RequestScope) error {
    var req CreateUserRequest
    if err := util.ReadJsonBody(scope.Request(), &req); err != nil {
        return events.BadRequestError.WithPayload(
            "application/json",
            []byte(`{"error":"invalid_request","message":"Request body must be valid JSON"}`),
        )
    }
    
    if err := validateUser(&req); err != nil {
        payload, _ := json.Marshal(map[string]string{
            "error": "validation_failed",
            "message": err.Error(),
        })
        return events.BadRequestError.WithPayload("application/json", payload)
    }
    
    // ...
}
```

#### Attach Metadata to Events

```go
func redirectToLogin(w http.ResponseWriter, scope we.RequestScope) error {
    returnUrl := scope.Request().URL.Path
    
    return events.FoundRedirect.
        WithAttribute("/login?return=" + url.QueryEscape(returnUrl))
}
```

### Custom Error Handlers

#### Implement Custom Error Handler for Consistent Responses

```go
type apiErrorHandler struct{}

func (h *apiErrorHandler) HandleError(w we.ResponseWriter, err error, scope we.RequestScope) {
    var weEvent events.WeEvent
    var statusCode int
    var message string
    
    if errors.As(err, &weEvent) {
        statusCode = weEvent.StatusCode()
        
        // Use custom payload if present
        if payload := weEvent.Payload(); payload != nil {
            w.Header().Set("Content-Type", payload.ContentTypeHint)
            w.WriteHeader(statusCode)
            w.Write(payload.Content)
            return
        }
        
        message = http.StatusText(statusCode)
    } else {
        statusCode = 500
        message = "Internal Server Error"
    }
    
    // Standard JSON error format
    response := map[string]interface{}{
        "error": http.StatusText(statusCode),
        "message": message,
        "timestamp": time.Now().Unix(),
    }
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(response)
}

// Use it
engine := we.New()
engine.SetErrorHandler(&apiErrorHandler{})
```

#### Log Errors Appropriately

```go
func (h *apiErrorHandler) HandleError(w we.ResponseWriter, err error, scope we.RequestScope) {
    var weEvent events.WeEvent
    statusCode := 500
    
    if errors.As(err, &weEvent) {
        statusCode = weEvent.StatusCode()
    }
    
    // Log server errors (5xx) with full details
    if statusCode >= 500 {
        log.Printf("ERROR [%d] %s %s: %v", 
            statusCode,
            scope.Request().Method,
            scope.Request().URL.Path,
            err,
        )
    } else {
        // Log client errors (4xx) with minimal info
        log.Printf("WARN [%d] %s %s",
            statusCode,
            scope.Request().Method,
            scope.Request().URL.Path,
        )
    }
    
    // ... send response
}
```

### Panic Recovery

The framework automatically recovers from panics, but avoid them:

```go
// BAD - Might panic
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    data := scope.Get("data").(MyType) // Panic if type assertion fails
    // ...
}

// GOOD - Safe type assertion
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    data, ok := scope.Get("data").(MyType)
    if !ok {
        return events.InternalServerError
    }
    // ...
}
```

## Performance Optimization

### Route Registration

#### Register Routes Before Starting Server

```go
// GOOD - Register all routes during initialization
engine := we.New()
engine.Handle("/users", listUsers)
engine.Handle("/users/{id}", getUser)
engine.HandleMethod("POST", "/users", createUser)

// Start server (path trees are now immutable)
engine.Listen(":8080")
```

Path trees are read-only after setup and thread-safe for concurrent requests.

### Path Matching

#### Use Specific Paths Over Wildcards When Possible

```go
// BETTER - Exact match (fastest)
engine.Handle("/api/health", healthCheck)

// SLOWER - Variable match
engine.Handle("/api/{resource}", genericHandler)

// SLOWEST - Wildcard match
engine.Handle("/api/**", catchAll)
```

Precedence also affects performance:
- Exact paths: O(k) where k = path depth
- Variables: Requires variable extraction
- Wildcards: Must check multiple patterns

### Session Management

#### Use Appropriate Session Storage for Scale

```go
// Development/Single Instance - In-Memory (default)
engine.SetSessionManager(we.DefaultSessionManager(config))

// Production/Multi-Instance - External Storage
type RedisSessionStorage struct {
    client *redis.Client
}

func (s *RedisSessionStorage) Get(ctx context.Context, id string) *we.Session {
    // Fetch from Redis
}

func (s *RedisSessionStorage) Put(ctx context.Context, session *we.Session) *we.Session {
    // Store in Redis
}

// Use custom storage
sessionManager := we.DefaultSessionManager(config)
sessionManager.SetStorage(&RedisSessionStorage{client: redisClient})
engine.SetSessionManager(sessionManager)
```

#### Configure Session Timeouts Appropriately

```go
// Short timeout for sensitive operations (banking, admin)
config := we.SessionManagerConfiguration{
    SessionTimeout: 15 * time.Minute,
    StaticSessionLifespan: true, // Absolute timeout
}

// Longer timeout for general apps
config := we.SessionManagerConfiguration{
    SessionTimeout: 24 * time.Hour,
    StaticSessionLifespan: false, // Rolling timeout (activity-based)
}
```

#### Don't Store Large Objects in Sessions

```go
// BAD - Large objects in session
scope.SetInSession("user_profile", largeUserObject) // Stored in memory/storage

// GOOD - Store only identifier, fetch when needed
scope.SetInSession("user_id", userID)

// Later, fetch from database
userId := scope.GetFromSession("user_id")
user := userRepository.FindById(userId)
```

### Response Writing

#### Use Efficient JSON Encoding

```go
// Use built-in helpers
util.ReplyJson(w, data)        // Standard encoding
util.DumpedReplyJson(w, data)  // Pretty-printed (development only)
```

#### Stream Large Responses

```go
func exportUsers(w http.ResponseWriter, scope we.RequestScope) error {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(200)
    
    encoder := json.NewEncoder(w)
    
    // Stream results as they're fetched
    w.Write([]byte("["))
    first := true
    
    for user := range userRepository.StreamAll() {
        if !first {
            w.Write([]byte(","))
        }
        encoder.Encode(user)
        first = false
    }
    
    w.Write([]byte("]"))
    return nil
}
```

### Filter Performance

#### Keep Filters Lightweight

Filters run on every request - keep them fast:

```go
// BAD - Heavy computation in filter
func (f *myFilter) Filter(headers http.Header, scope we.RequestScope) error {
    // Expensive database query on every request
    config := loadConfigFromDatabase()
    // ...
}

// GOOD - Cache expensive operations
var configCache = loadConfigOnce()

func (f *myFilter) Filter(headers http.Header, scope we.RequestScope) error {
    config := configCache
    // ...
}
```

#### Order Filters by Frequency of Short-Circuit

```go
// GOOD - Fast rejections first
engine.AddFilter(rateLimitFilter)    // Rejects quickly if over limit
engine.AddFilter(corsFilter)          // Fast header checks
engine.AddFilter(securityFilter)      // May authenticate (slower)
engine.AddFilter(loggingFilter)       // Runs on successful requests
```

## Session Management

### Session Lifecycle

#### Check Session Existence Before Use

```go
func profileHandler(w http.ResponseWriter, scope we.RequestScope) error {
    if !scope.HasSession() {
        return events.InternalServerError // Sessions not configured
    }
    
    userId := scope.GetFromSession("user_id")
    if userId == nil {
        return events.UnauthorizedError
    }
    
    // ...
}
```

#### Use Session Status to Differentiate New vs Existing

```go
func trackVisits(w http.ResponseWriter, scope we.RequestScope) error {
    if scope.HasSession() {
        session := // access internal session if needed
        
        if session.Status == we.SessionStatusNew {
            // First visit
            scope.SetInSession("visit_count", 1)
        } else {
            // Returning visitor
            count := scope.GetFromSession("visit_count").(int)
            scope.SetInSession("visit_count", count+1)
        }
    }
    
    // ...
}
```

### Security Considerations

#### Regenerate Session After Login

```go
func login(w http.ResponseWriter, scope we.RequestScope) error {
    // Validate credentials
    user, err := authenticateUser(username, password)
    if err != nil {
        return events.UnauthorizedError
    }
    
    // Get current session ID (to delete old session)
    // Note: go-we doesn't expose session ID directly
    // Consider using session storage with custom invalidation
    
    // Set new session data
    scope.SetInSession("user_id", user.ID)
    scope.SetInSession("login_time", time.Now())
    
    return nil
}
```

#### Clear Session on Logout

```go
// Note: go-we doesn't provide explicit session.Invalidate()
// You can clear all session attributes manually

func logout(w http.ResponseWriter, scope we.RequestScope) error {
    if scope.HasSession() {
        // Clear sensitive data
        scope.SetInSession("user_id", nil)
        scope.SetInSession("auth_token", nil)
        // Clear other session attributes as needed
    }
    
    return events.FoundRedirect.WithAttribute("/")
}
```

#### Set Secure Cookie Flags

```go
config := we.SessionManagerConfiguration{
    SessionTimeout: time.Hour,
    CookieName: "session",
    // Additional cookie configuration
    CookiePath: "/",
    CookieDomain: "example.com",
    CookieHttpOnly: true,
    CookieSecure: true, // HTTPS only
    CookieSameSite: http.SameSiteStrictMode,
}
```

## Filter Configuration

### Filter Order Matters

```go
// CORRECT ORDER
engine.AddFilter(corsFilter)         // 1. CORS (early reject)
engine.AddFilter(securityFilter)     // 2. Authentication
engine.AddFilter(loggingFilter)      // 3. Logging (after auth)
engine.AddFilter(headersFilter)      // 4. Security headers

// WRONG ORDER - Don't do this
engine.AddFilter(securityFilter)     // Auth before CORS = CORS won't work
engine.AddFilter(corsFilter)
```

Recommended order:
1. **CORS** - Handle preflight requests early
2. **Rate Limiting** - Reject abusive requests
3. **Security/Authentication** - Identify users
4. **Authorization** - Check permissions
5. **Logging** - Log authenticated requests
6. **Response Headers** - Add security headers

### Use Path-Specific Configuration

```go
// GOOD - Different security for different paths
securityFilter := security.Filter(true).
    Authentication(sessionAuth).
    
    Path("/api/**").
        Authentication(bearerAuth). // APIs use tokens
        Add().
    
    Path("/public/**").
        Anonymous(). // Public content
        Add().
    
    Build()
```

## Production Deployment

### Graceful Shutdown

```go
var shutdown func(time.Duration) error

engine := we.New()
engine.HookGraciousShutdownFunction(&shutdown)

// Handle OS signals
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

go func() {
    <-sigChan
    log.Println("Shutting down gracefully...")
    
    // Give handlers 30 seconds to complete
    if err := shutdown(30 * time.Second); err != nil {
        log.Printf("Shutdown error: %v", err)
    }
    
    os.Exit(0)
}()

engine.Listen(":8080")
```

### TLS Configuration

```go
// Use strong TLS configuration
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    },
    PreferServerCipherSuites: true,
}

engine.ListenWithTlsOptions(":8443", tlsConfig)
```

### Health Checks

```go
engine.Handle("/health", func(w http.ResponseWriter, scope we.RequestScope) error {
    // Check dependencies
    if err := database.Ping(); err != nil {
        w.WriteHeader(503)
        w.Write([]byte("Database unavailable"))
        return nil
    }
    
    w.WriteHeader(200)
    w.Write([]byte("OK"))
    return nil
})
```

## Testing Guidelines

### Use RequestScopeMocker for Unit Tests

```go
import "github.com/gomatbase/go-we/test"

func TestUserHandler(t *testing.T) {
    // Create mock scope
    mocker := test.RequestScopeMocker{
        Variables: map[string]string{"id": "123"},
        Parameters: map[string][]string{"format": {"json"}},
    }
    scope := mocker.Mock()
    
    // Create response recorder
    w := httptest.NewRecorder()
    
    // Test handler
    err := getUserHandler(w, scope)
    
    if err != nil {
        t.Fatalf("Handler returned error: %v", err)
    }
    
    if w.Code != 200 {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
}
```

### Test Error Paths

```go
func TestUserHandler_NotFound(t *testing.T) {
    mocker := test.RequestScopeMocker{
        Variables: map[string]string{"id": "999"},
    }
    scope := mocker.Mock()
    w := httptest.NewRecorder()
    
    err := getUserHandler(w, scope)
    
    // Should return NotFoundError event
    if !errors.Is(err, events.NotFoundError) {
        t.Errorf("Expected NotFoundError, got %v", err)
    }
}
```

### Integration Testing

```go
func TestAPIIntegration(t *testing.T) {
    engine := we.New()
    engine.Handle("/api/users/{id}", getUserHandler)
    
    // Create test server
    server := httptest.NewServer(engine.Handler())
    defer server.Close()
    
    // Make request
    resp, err := http.Get(server.URL + "/api/users/123")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        t.Errorf("Expected status 200, got %d", resp.StatusCode)
    }
    
    // Verify response body
    var user User
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        t.Fatal(err)
    }
    
    if user.ID != 123 {
        t.Errorf("Expected user ID 123, got %d", user.ID)
    }
}
```

## Summary

Following these best practices will help you build secure, performant, and maintainable applications with go-we:

- **Security**: Use authentication, validate input, configure CORS properly, implement security headers
- **Error Handling**: Use WeEvents for declarative flow control, implement custom error handlers for consistency
- **Performance**: Choose appropriate data structures, optimize filter order, use efficient session storage
- **Session Management**: Configure timeouts appropriately, protect sensitive data, handle session lifecycle correctly
- **Production**: Implement graceful shutdown, use TLS, configure health checks
- **Testing**: Use provided test utilities, test error paths, write integration tests

For more details, see:
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [README.md](../README.md) - Getting started and examples
- Package documentation - Detailed API reference
