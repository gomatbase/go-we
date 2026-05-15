# Custom Filters Example

This example demonstrates how to create and use custom filters (middleware) in go-we.

## What You'll Learn

- How to create custom filters
- Filter execution order
- Request/response modification in filters
- Short-circuiting request processing with filters
- Using built-in CORS and security headers filters
- Sharing data between filters and handlers using RequestScope

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

### Public Endpoints

```bash
# Home page with examples
curl http://localhost:8080/

# Public endpoint
curl http://localhost:8080/public
```

### Protected Endpoint (API Key Required)

```bash
# Without API key (will return 401)
curl http://localhost:8080/api/protected

# With API key (will succeed)
curl -H "X-API-Key: secret-api-key-123" http://localhost:8080/api/protected
```

### Rate Limited Endpoint

```bash
# Try this more than 10 times in a minute to see rate limiting
for i in {1..12}; do 
  curl http://localhost:8080/api/rate-limited
  echo ""
done
```

### Content-Type Validation

```bash
# POST without JSON content-type (will return 415)
curl -X POST http://localhost:8080/api/data

# POST with JSON content-type (will succeed)
curl -X POST -H "Content-Type: application/json" \
     -d '{"test": "data"}' \
     http://localhost:8080/api/data
```

### CORS Preflight

```bash
# Test CORS preflight request
curl -X OPTIONS \
     -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     -H "Access-Control-Request-Headers: Content-Type" \
     http://localhost:8080/api/data -v
```

## Key Concepts

### Filter Function Signature

Filters have full access to the request but can only modify response headers. If they want
to intercept the request and respond early, they can do so by returning a `WeEvent` error of the
appropriate type (e.g. `UnauthorizedError`, `TooManyRequestsError`, etc.), including a 200 response
WeEvent (which implements error and for all purposes is handled as an error).

```go
func myFilter(headers http.Header, scope we.RequestScope) error {
    // Filters receive:
    // - headers: Response headers (can be modified)
    // - scope: Request scope with full request context
    
    // Return nil to continue processing
    return nil
    
    // Return WeEvent to short-circuit and send error response
    // return events.UnauthorizedError
}
```

### Registering Filters

```go
// Wrap function as filter
builder.Filter(we.FilterFunction(myFilter))

// Or use built-in filters
builder.AddFilter(filters.Cors().Build())
```

### Filter Execution Order

Filters execute in **registration order**:

```go
builder.
    Filter(we.FilterFunction(firstFilter)).  // Runs 1st 
    Filter(we.FilterFunction(secondFilter)). // Runs 2nd
    Filter(we.FilterFunction(thirdFilter))   // Runs 3rd
// Then handler executes if filters do not return events that may break the chain
```

**Important:** Order matters! For example:
- CORS filter should run early to handle preflight requests
- Authentication should run before authorization (in-built security filter handles both in the correct order)
- Logging often runs first or last depending on what you want to log

### Modifying Response Headers

```go
func customHeaderFilter(headers http.Header, scope we.RequestScope) error {
    // Add custom header
    headers.Set("X-Custom-Header", "value")
    
    // Add security headers
    headers.Set("X-Frame-Options", "DENY")
    
    return nil
}
```

### Storing Data in Request Scope

Filters can share data with handlers via RequestScope:

```go
func setupFilter(headers http.Header, scope we.RequestScope) error {
    // Store data
    scope.Set("request_id", generateId())
    scope.Set("start_time", time.Now())
    
    return nil
}

func handler(w http.ResponseWriter, scope we.RequestScope) error {
    // Retrieve data
    requestId := scope.Get("request_id").(string)
    startTime := scope.Get("start_time").(time.Time)
    
    // Use the data...
    return nil
}
```

### Short-Circuiting Requests

Return a `WeEvent` error to stop request processing:

```go
func authFilter(headers http.Header, scope we.RequestScope) error {
    apiKey := scope.Request().Header.Get("X-API-Key")
    
    if apiKey != "valid-key" {
        // Stop processing and return 401
        return events.UnauthorizedError
    }
    
    // Continue to next filter/handler
    return nil
}
```

## Built-in Filters

### CORS Filter

Handles Cross-Origin Resource Sharing:

```go
corsFilter := filters.Cors().
    AllowedOrigins("https://example.com").    // Allowed origins
    AllowedMethods("GET", "POST", "PUT").     // Allowed HTTP methods
    AllowedHeaders("Content-Type").           // Allowed headers
    AllowCredentials().                       // Allow cookies
    MaxAge(3600).                            // Preflight cache time (seconds)
    Build()

engine.AddFilter(corsFilter)
```

**Common Configurations:**

```go
// Development (allow all origins - NOT for production)
corsFilter := filters.Cors().
    AllowedOrigins("*").
    AllowedMethods("*").
    AllowedHeaders("*").
    Build()

// Production (specific origins)
corsFilter := filters.Cors().
    AllowedOrigins("https://app.example.com", "https://admin.example.com").
    AllowedMethods("GET", "POST", "PUT", "DELETE").
    AllowedHeaders("Content-Type", "Authorization").
    AllowCredentials().
    MaxAge(86400). // 24 hours
    Build()
```

### Response Headers Filter

Supports configuring security-related HTTP headers as well as injecting any custom headers as needed:

```go
securityFilter := filters.ResponseHeaders().
    HSTS(31536000, true, false).                  // HTTP Strict Transport Security
    CSP("default-src 'self'").                    // Content Security Policy
    FrameOptions(filters.FrameOptionDeny).        // Clickjacking protection
    NoSniff().                                    // MIME-sniffing protection
    ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin).
    Build()

engine.AddFilter(securityFilter)
```

**Security Header Options:**

```go
// HSTS - HTTP Strict Transport Security
HSTS(maxAge, includeSubDomains, preload)
HSTS(31536000, true, false) // 1 year, subdomains, no preload

// X-Frame-Options - Clickjacking protection
FrameOptions(filters.FrameOptionDeny)       // Block all framing
FrameOptions(filters.FrameOptionSameOrigin) // Allow same origin

// X-Content-Type-Options
NoSniff()              // Enable (default)
DisableNoSniff()       // Disable

// Content Security Policy
CSP("default-src 'self'; script-src 'self' 'unsafe-inline'")

// Referrer Policy
ReferrerPolicy(filters.ReferrerPolicyNoReferrer)
ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin)
```

## Common Filter Patterns

### Request Logging

```go
func loggingFilter(headers http.Header, scope we.RequestScope) error {
    start := time.Now()
    scope.Set("start_time", start)
    
    log.Printf("[%s] %s %s", 
        scope.Request().Method, 
        scope.Request().URL.Path,
        scope.Request().RemoteAddr)
    
    return nil
}
```

### Request ID Generation

```go
func requestIdFilter(headers http.Header, scope we.RequestScope) error {
    requestId := uuid.New().String()
    headers.Set("X-Request-ID", requestId)
    scope.Set("request_id", requestId)
    return nil
}
```

### API Key Authentication

```go
func apiKeyFilter(headers http.Header, scope we.RequestScope) error {
    apiKey := scope.Request().Header.Get("X-API-Key")
    
    if !isValidApiKey(apiKey) {
        return events.UnauthorizedError
    }
    
    scope.Set("api_key", apiKey)
    return nil
}
```

### Rate Limiting

```go
func rateLimitFilter(headers http.Header, scope we.RequestScope) error {
    ip := scope.Request().RemoteAddr
    
    if isRateLimited(ip) {
        return events.New(429, "Too Many Requests")
    }
    
    incrementRateLimit(ip)
    return nil
}
```

### Content-Type Validation

```go
func contentTypeFilter(headers http.Header, scope we.RequestScope) error {
    if scope.Request().Method == "POST" || scope.Request().Method == "PUT" {
        ct := scope.Request().Header.Get("Content-Type")
        if !strings.HasPrefix(ct, "application/json") {
            return events.New(415, "Unsupported Media Type")
        }
    }
    return nil
}
```

## Filter vs. Handler

**When to use a Filter:**
- Cross-cutting concerns (logging, auth, CORS)
- Logic that applies to multiple routes or globally
- Request/response (headers) modification
- Early validation/rejection
- Exceptions to normal request lifecycle (e.g. short-circuiting)

**When to use a Handler:**
- Route-specific business logic
- Generating response content
- Database operations
- Complex processing unique to one endpoint

## Path-Based Filtering

Filters are applied to all incoming requests. Filter implementations may support
path specific configuration (e.g. CORS and ResponseHeaders filters).

```go
import "github.com/gomatbase/go-we/security"

securityFilter := security.Filter(false). // Allow all by default
    Path("/admin/**").
        Authentication(authProvider).
        Build()
```

This example shows manual per-handler filtering for demonstration. In production, use the security package for 
path-based security filter application.

## Best Practices

1. **Order matters** - Add filters in logical order (CORS → Auth → Rate limit → etc.)
2. **Use RequestScope** - Share data between filters and handlers
3. **Fail fast** - Return early from filters when possible
4. **Be efficient** - Filters run on every request
5. **Use built-in filters** - CORS and security headers are production-ready
6. **Don't mutate request** - Modify response headers, not the request. If you need to also process the request, make sure to reset body after reading so handlers may still process the request body.
7. **Handle errors gracefully** - Return WeEvent errors for proper error responses

## Next Steps

- Move on to [05-basic-auth](../05-basic-auth/) for authentication examples
- See [08-authorization](../08-authorization/) for path-based filtering with the security package
- Read [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) for filter patterns in production
- Check [ARCHITECTURE](../../docs/ARCHITECTURE.md) for filter chain internals
