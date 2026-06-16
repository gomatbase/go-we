# go-we Architecture

This document describes the internal architecture and design of the go-we web framework.

## Table of Contents

- [Overview](#overview)
- [Core Components](#core-components)
- [Request Flow](#request-flow)
- [Path Matching System](#path-matching-system)
- [Filter Chain](#filter-chain)
- [Session Management](#session-management)
- [Security Architecture](#security-architecture)
- [Event-Driven Error Handling](#event-driven-error-handling)
- [Design Patterns](#design-patterns)

## Overview

go-we is a lightweight HTTP web framework that implements the `http.Handler` interface. It provides a feature-rich alternative to Go's standard `http.DefaultServeMux` while maintaining simplicity and performance.

### Key Design Goals

1. **Minimal Dependencies** - Keep external dependencies to a minimum
2. **Type Safety** - Leverage Go's type system for compile-time safety
3. **Flexibility** - Provide pluggable interfaces for customization
4. **Developer Experience** - Fluent builders and clear APIs
5. **Performance** - Efficient path matching and minimal allocations

## Core Components

### WebEngine

The `engine` is the central component that implements `http.Handler`. It is created using a builder pattern and manages:

- **Path Trees** - Separate trees for each HTTP method plus an "ALL" tree
- **Filters** - Ordered list of filters to execute before handlers
- **Session Manager** - Optional session management
- **Error Handler** - Customizable error handling
- **Server Configuration** - Timeout settings and server options

```go
type engine struct {
    matchTrees        map[string]pathTree.Tree[HandlerFunction]
    filters           []Filter
    sessionManager    SessionManager
    errorHandler      ErrorHandler
    server            *http.Server
    readHeaderTimeout time.Duration
    readTimeout       time.Duration
    writeTimeout      time.Duration
    idleTimeout       time.Duration
    maxHeaderBytes    int
}
```

**Creating the Engine:**

The engine is created using a fluent builder API:

```go
engine := we.New().
    Handle("/", homeHandler).
    HandleMethod("GET", "/users", listUsers).
    HandleMethod("POST", "/users", createUser).
    Filter(corsFilter).
    Filter(securityFilter).
    SessionManager(sessionManager).
    ErrorHandler(customErrorHandler).
    ReadHeaderTimeout(15 * time.Second).
    Build()
```

This builder pattern provides:
- Type-safe configuration
- Compile-time validation
- Immutable engine after building
- Clear separation between configuration and runtime

### RequestScope

The `RequestScope` interface wraps `http.Request` and provides convenient access to:

- Path variables extracted from the URL
- Query parameters
- Request-scoped attributes
- Session access through Session interface
- The underlying request context
- Request creation timestamp

This abstraction decouples handlers from direct HTTP dependencies and makes testing easier.

```go
type requestScope struct {
    request    *http.Request
    attributes map[string]any
    variables  map[string]string
    session    Session      // Session interface, not pointer
    timestamp  time.Time    // Request creation timestamp
}
```

**Accessing Session:**

The RequestScope provides a `Session()` method that returns a Session interface:

```go
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    // Access session through interface
    if scope.HasSession() {
        scope.Session().Set("user_id", "123")
        userId := scope.Session().Get("user_id")
    }
    return nil
}
```

### HandlerFunction

Handlers in go-we return `error` instead of being void like standard `http.HandlerFunc`. This enables declarative error handling through events:

```go
type HandlerFunction func(http.ResponseWriter, RequestScope) error
```

Returning an error (typically a `WeEvent`) triggers the error handling flow.

## Request Flow

Here's the complete request processing flow:

```
1. HTTP Request arrives
   ↓
2. WebEngine.ServeHTTP() called
   ↓
3. Create RequestScope
   ↓
4. Get/Create Session (if session manager configured)
   ↓
5. Wrap ResponseWriter (track if response started)
   ↓
6. Execute Filter Chain (in order)
   ↓
   ├─→ Filter returns error → Handle Error → END
   │
   └─→ All filters pass
       ↓
7. Match path to handler (with precedence rules)
   ↓
   ├─→ No match → 404 Error → END
   │
   └─→ Handler found
       ↓
8. Execute Handler
   ↓
   ├─→ Handler returns error → Handle Error → END
   │
   └─→ Handler succeeds → END
```

### Error Handling Flow

```
Error occurs
   ↓
Is error a WeEvent?
   ├─→ Yes: Use event's status code and payload
   └─→ No: Wrap as 500 Internal Server Error
       ↓
Has response already started?
   ├─→ Yes: Log error, cannot send new response
   └─→ No: 
       ↓
   Custom ErrorHandler configured?
       ├─→ Yes: Call ErrorHandler.HandleError()
       └─→ No: Use default error handler
           ↓
       Set status code
       Write payload (if any)
```

## Path Matching System

go-we uses a **Trie-based path tree** for efficient route matching.

### Path Tree Structure

Each node in the tree represents a path segment and can have:

- **Exact children** - Literal path segments (`/users`)
- **Variable child** - Single variable segment (`{id}`)
- **Single wildcard** - Matches one segment (`*`)
- **Double wildcard** - Matches remaining path (`**`)

```
Root
 ├─ users (exact)
 │   ├─ {id} (variable)
 │   │   └─ posts
 │   └─ * (single wildcard)
 ├─ api (exact)
 │   └─ ** (double wildcard)
 └─ ** (catch-all)
```

### Matching Algorithm

When a request arrives for `/users/123/posts`:

1. Split path into parts: `["users", "123", "posts"]`
2. Traverse tree starting from root
3. At each level, try to match in this order:
   - **Exact match** (highest priority)
   - **Variable match** (captures value)
   - **Single wildcard** (one segment)
   - **Double wildcard** (lowest priority)
4. Return first complete match found

### Precedence Rules

When multiple patterns match a path, precedence is:

1. **Exact paths** - `/users/123` (highest)
2. **Path variables** - `/users/{id}`
3. **Single wildcard** - `/users/*`
4. **Double wildcard** - `/users/**` (lowest)

**Example:**

```go
engine := we.New().
    Handle("/api/health", healthHandler).      // Exact
    Handle("/api/{resource}", resourceHandler). // Variable
    Handle("/api/*", singleWildcardHandler).    // Single wildcard
    Handle("/api/**", doubleWildcardHandler).   // Double wildcard
    Build()

// Request: /api/health
// Matches: healthHandler (exact wins)

// Request: /api/users
// Matches: resourceHandler (variable wins over wildcards)

// Request: /api/v1/users
// Matches: doubleWildcardHandler (only double wildcard matches)
```

### Wildcard Behavior

**Single Wildcard (`*`):**
- Matches exactly one path segment
- Does NOT match empty segments
- `/api/*` matches `/api/users` but NOT `/api` or `/api/v1/users`

**Double Wildcard (`**`):**
- Matches zero or more remaining segments
- `/api/**` matches `/api`, `/api/users`, `/api/v1/users`, etc.

**Root Path Special Case:**
- As of v1.0, `/*` and `/**` also match the root path `/`
- This eliminates the need for separate `/` and `/**` registrations

## Filter Chain

Filters execute before the handler and can:

1. **Modify the request** - Add headers, set attributes
2. **Short-circuit** - Return early without calling handler
3. **Control flow** - Redirect, return errors, etc.

### Filter Interface

```go
type Filter interface {
    Filter(http.Header, RequestScope) error
}
```

Filters receive:
- **http.Header** - Response headers (can be modified)
- **RequestScope** - Full request context

### Filter Execution Order

Filters execute in **registration order**:

```go
engine := we.New().
    Filter(loggingFilter).    // Executes first
    Filter(corsFilter).       // Executes second
    Filter(securityFilter).   // Executes third
    Build()
// ... then handler
```

**Best Practice:** Order matters!
- Authentication/CORS should be early
- Authorization after authentication
- Logging can be first or last depending on needs

### Filter Return Values

Filters can return:

- **`nil`** - Continue to next filter/handler
- **`WeEvent`** - Filter returns a flow control instruction. Flow is affect depending on the type of the event status code
    - `events.RequestFlow` (1XX events) - Special flow control status codes which won't be returned to the client
        - `events.Continue` - Break filter chain and continue to handle request
        - `events.Update` - continue to next filter but update request scope's path
  - `events.Interruption` (2XX events) - Break filter chain and return response with event's payload, content type and status code
  - `events.Redirection` (3XX events) - Break filter chain and return response of type redirection with the event providing the location to redirect to
  - other - WeEvent is considered a normal error and will be handled by the error handler
- **Other errors** - will be handled by the error handler, which by default will result in a 500 response

### Path-Specific Filter Configuration

Filters apply to any incoming request, if path specific configurations are required, the filter itself should handle it.
Several provided filters support path-specific configuration, allowing different behavior for different paths using the same wildcard matching system as the router.

#### Example: CORS with Path-Specific Configuration

```go
corsFilter := filters.Cors().
    // Default: restrictive for all paths
    AllowedOrigins("https://example.com").
    AllowedMethods("GET", "POST").
    
    // Public API: allow all origins
    Path("/api/public/**").
        AllowedOrigins("*").
        AllowedMethods("GET").
        Add().
    
    // Admin API: very restrictive
    Path("/api/admin/**").
        AllowedOrigins("https://admin.example.com").
        AllowedMethods("GET", "POST", "PUT", "DELETE").
        AllowCredentials().
        Add().
    
    // Internal endpoints: disable CORS entirely
    Path("/health", "/metrics", "/internal/*").
        Disabled().
        Add().
    
    Build()

engine := we.New().
    Filter(corsFilter).
    Build()
```

**Request matching examples:**

- Request to `/api/public/users` → Uses "Public API" config (allow all origins)
- Request to `/api/admin/settings` → Uses "Admin API" config (restrictive)
- Request to `/health` → CORS disabled (no headers added)
- Request to `/api/orders` → Uses default config (restrictive)

#### Example: ResponseHeaders with Path-Specific Configuration

```go
headersFilter := filters.ResponseHeaders().
    // Default: secure headers for all paths
    HSTS(31536000, true, false).
    FrameOptions(filters.FrameOptionSameOrigin).
    
    // API endpoints: add versioning header, disable frame options
    Path("/api/**").
        Header("X-API-Version", "v2.0").
        Header("Cache-Control", "no-store").
        DisableFrameOptions().
        Add().
    
    // Public assets: allow embedding, add caching
    Path("/assets/**").
        FrameOptions(filters.FrameOptionDeny).
        Header("Cache-Control", "public, max-age=31536000").
        Add().
    
    // Health checks: no security headers
    Path("/health", "/metrics").
        Disabled().
        Add().
    
    Build()

engine := we.New().
    Filter(headersFilter).
    Build()
```

**Path precedence example:**

Given these configurations:
- `/api/users` (exact)
- `/api/*` (single wildcard)
- `/api/**` (double wildcard)

Request to `/api/users` → Matches exact path first (highest precedence)
Request to `/api/admin` → Matches `/api/*` (second highest)
Request to `/api/v1/users` → Matches `/api/**` only (lowest precedence)

This path-specific configuration architecture provides fine-grained control while maintaining a clean, declarative API.

## Session Management

### Session Interface

Sessions are accessed through a clean interface that provides:

```go
type Session interface {
    Get(key string) any
    Set(key string, value any)
    Delete(key string)
    Clear()
}
```

The underlying `SessionObject` implements this interface and contains:

```go
type SessionObject struct {
    Status     uint           // SessionStatusNew or SessionStatusExisting
    LastUse    time.Time      // Timestamp of last session use
    Id         string         // Unique session identifier
    Attributes map[string]any // Session data storage
}
```

**Using Sessions:**

```go
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    if scope.HasSession() {
        // Set values
        scope.Session().Set("user_id", "123")
        scope.Session().Set("username", "john")
        
        // Get values
        userId := scope.Session().Get("user_id")
        
        // Delete specific key
        scope.Session().Delete("temp_data")
        
        // Clear all session data
        scope.Session().Clear()
    }
    return nil
}
```

### Session Lifecycle

```
Request arrives
   ↓
Cookie present?
   ├─→ No: Create new session
   │        ↓
   │   Set cookie in response
   │        ↓
   │   Status = SessionStatusNew
   │
   └─→ Yes: Lookup session in storage
            ↓
        Found and valid?
            ├─→ No: Create new session
            │
            └─→ Yes: 
                  ↓
              Rolling session?
                  ├─→ Yes: Update LastUse timestamp
                  └─→ No: Keep original LastUse
                      ↓
              Status = SessionStatusExisting
```

### Session Storage

Sessions can use:

1. **In-Memory Storage** (default)
   - Fast but not persistent
   - Lost on server restart
   - Not suitable for multi-instance deployments

2. **Custom Storage** (implement `SessionStorage` interface)
   - Database-backed
   - Redis/Memcached
   - Distributed storage

```go
type SessionStorage interface {
    Get(ctx context.Context, sessionId string) *SessionObject
    Put(ctx context.Context, session *SessionObject) *SessionObject
    Delete(ctx context.Context, sessionId string) *SessionObject
    PurgeOlderThan(ctx context.Context, age time.Duration)
}
```

**Configuring Sessions:**

Sessions are configured using a builder pattern and attached to the engine:

```go
sessionManager := we.DefaultSessionManager().
    SessionTimeout(2 * time.Hour).
    CookieName("myapp_session").
    CookieSecure(true).
    CookieSameSite(http.SameSiteStrictMode).
    Build()

engine := we.New().
    SessionManager(sessionManager).
    Handle("/", handler).
    Build()
```

### Session Modes

**Rolling Sessions** (`StaticSessionLifespan = false`):
- Session expires after N minutes of **inactivity**
- Each request refreshes the expiration
- Better user experience

**Static Sessions** (`StaticSessionLifespan = true`):
- Session expires N minutes after **creation**
- Activity does not extend lifetime
- More secure for sensitive operations

### Background Purging

A background goroutine periodically cleans expired sessions:

```go
func (sm *sessionManager) purgeLoop(interval time.Duration) {
    ticker := time.NewTicker(interval)
    for range ticker.C {
        sm.storage.PurgeOlderThan(context.Background(), sm.timeout)
    }
}
```

Default purge interval: 1 minute

## Security Architecture (Security Filter)

### Multi-Layer Security Model

```
Request
   ↓
Security Filter
   ↓
1. Try each configured Authentication Provider (in order)
   ↓
   Found user?
   ├─→ No: Check if path allows anonymous
   │       ├─→ Yes: Continue (no user)
   │       └─→ No: Return 401/403
   │
   └─→ Yes: Store user in scope
       ↓
2. Apply Authorization Rules
   ↓
   Authorized?
   ├─→ No: Return 403
   └─→ Yes: 
       ↓
3. Execute Authentication Triggers (if any)
   ↓
Continue filter chain or to handler (user available via GetUser()), if last filter in the chain.
```

### Authentication Providers

Each provider implements:

```go
type AuthenticationProvider interface {
    Authenticate(headers http.Header, scope RequestScope) (*User, error)
    Realm() string
    IsValid(user *User) bool
    Challenge() string
    Endpoints() []string
}
```

**Provider Types:**

1. **Basic Authentication** - HTTP Basic Auth
2. **Bearer Token** - JWT/OAuth2 tokens
3. **Form-Based** - Traditional login forms
4. **SSO** - OAuth2/OpenID Connect
5. **mTLS** - Client certificates
6. **Anonymous** - Public access

### Path-Based Configuration

Security can be configured per-path:

```go
security.Filter(restrictedByDefault).
    // Root-level auth (applies everywhere)
    Authentication(bearerAuthProvider).
    
    // Override for specific paths
    Path("/public/**").
        Anonymous().  // No auth required
    
    Path("/admin/**").
        Authorize(security.Scope("admin")).  // Extra check
    
    Build()

engine := we.New().
    Filter(securityFilter).
    Build()
```

### Authorization Rules

Authorization can use:

1. **Scope-based** - Check user has required scope
2. **Custom logic** - Implement `Authorization` interface
3. **Combinators** - `All()`, `Either()`

```go
// Requires admin AND manager scopes
auth := security.All(
    security.Scope("admin"),
    security.Scope("manager"),
)

// Requires admin OR moderator scope
auth := security.Either(
    security.Scope("admin"),
    security.Scope("moderator"),
)
```

### Realm-Based Multi-Tenancy

Multiple authentication providers can coexist by realm:

- Each provider has a unique realm
- User's realm is stored with the user
- `IsValid()` checks user's realm matches provider's realm

This allows:
- Different auth for different parts of the app
- API keys for APIs, sessions for web UI
- Gradual migration between auth methods

## Event-Driven Error Handling

### WeEvent Interface

Events represent both errors and flow control for filter chain handling:

```go
type WeEvent interface {
    error                                    // Is an error
    StatusCode() int                        // HTTP status
    Payload() *Payload                      // Response body
    WithPayload(string, []byte) WeEvent    // Add payload
    WithAttribute(any) WeEvent             // Add metadata
    Attribute() any                         // Get metadata
}
```

### Standard Events

**Success/Redirects:**
- `Continue` - Explicit continue (no-op)
- `OKInterruption` - Early success (200)
- `MovedPermanentlyRedirect` (301)
- `FoundRedirect` (302)
- `TemporaryRedirectRedirect` (307)
- `PermanentRedirectRedirect` (308)

**Client Errors (4xx):**
- `BadRequestError` (400)
- `UnauthorizedError` (401)
- `ForbiddenError` (403)
- `NotFoundError` (404)
- `MethodNotAllowedError` (405)
- `ConflictError` (409)

**Server Errors (5xx):**
- `InternalServerError` (500)
- `NotImplementedError` (501)
- `ServiceUnavailableError` (503)

### Event Immutability

Events are immutable - methods return new instances:

```go
base := events.BadRequestError

// Each WithPayload returns a NEW event
err1 := base.WithPayload("text/plain", []byte("Error 1"))
err2 := base.WithPayload("text/plain", []byte("Error 2"))

// err1 and err2 are independent
// base is unchanged
```

### Custom Error Handler

Implement `ErrorHandler` for custom error responses:

```go
type ErrorHandler interface {
    HandleError(error, http.ResponseWriter, RequestScope)
}
```

Use cases:
- Custom error page templates
- JSON error format for APIs
- Error tracking/logging
- Different formats per path

## Design Patterns

### 1. Builder Pattern

Extensively used for configuration of engine, filters, session manager, and security:

```go
// Engine builder
engine := we.New().
    Handle("/", homeHandler).
    Filter(corsFilter).
    SessionManager(sessionManager).
    Build()

// Security filter builder
securityFilter := security.Filter(true).
    Authentication(provider).
    Path("/admin/**").
        Authorize(scope).
        Add().
    Build()

// Session manager builder
sessionManager := we.DefaultSessionManager().
    SessionTimeout(2 * time.Hour).
    CookieSecure(true).
    Build()

// CORS filter builder
corsFilter := filters.Cors().
    AllowedOrigins("https://example.com").
    AllowedMethods("GET", "POST").
    AllowCredentials().
    Build()
```

**Benefits:**
- Type-safe configuration
- Readable, fluent API
- Compile-time validation
- Self-documenting
- Immutable after building
- Clear separation between configuration and runtime

### 2. Filter Chain (Chain of Responsibility)

Filters form a processing chain:

```go
filter1 → filter2 → filter3 → handler
```

Each filter can:
- Process and continue
- Stop the chain
- Modify context for downstream

**Similar to:** Servlet filters, Express middleware

### 3. Strategy Pattern

Pluggable implementations:

- `SessionStorage` - Different storage backends
- `AuthenticationProvider` - Different auth methods
- `Authorization` - Different auth logic
- `ErrorHandler` - Different error responses

### 4. Path Tree (Trie)

Custom trie implementation for efficient routing:

- **O(k) lookup** where k = path depth
- Better than linear search for many routes
- Supports variables and wildcards

### 5. Scope Pattern

`RequestScope` encapsulates request context:

- Prevents tight coupling to `http.Request`
- Makes testing easier
- Provides unified interface for variables, parameters, session

### 6. Event-Driven Architecture

Errors as events enable declarative control flow:

```go
// Declarative error handling
if unauthorized {
    return events.UnauthorizedError
}

if notFound {
    return events.NotFoundError
}

// Declarative redirects
if needsLogin {
    return events.FoundRedirect.WithAttribute("/login")
}
```

**Benefits:**
- Clear intent
- Consistent error handling
- Flow control through events

## Performance Considerations

### Path Matching

- **Efficient trie lookup**: O(k) where k is path depth
- **Minimal allocations**: Reuses path split results
- **Method-specific trees**: Separate trees avoid method checks

### Session Management

- **In-memory by default**: Fast access
- **Lazy creation**: Sessions only created when needed
- **Background purging**: Doesn't block requests

### Response Writer

- **Track state**: Know if response started (avoid duplicate writes)
- **Minimal overhead**: Simple wrapper, inline methods

### Filter Chain

- **Short-circuit on error**: Stop immediately on first error
- **No reflection**: Direct function calls

## Thread Safety

### Concurrent Access

- **Engine**: Immutable after Build() (thread-safe)
- **Path Trees**: Read-only after Build() (thread-safe)
- **Sessions**: Mutex-protected storage operations
- **RequestScope**: Per-request, not shared
- **Events**: Immutable (thread-safe)

### Shared State

Avoid shared mutable state in:
- Handlers (per-request scope)
- Filters (stateless preferred)

Use `RequestScope` for per-request state, not global variables.

## Summary

go-we's architecture provides:

1. **Efficient routing** via trie-based path matching
2. **Flexible filtering** through ordered filter chain
3. **Rich session management** with pluggable storage
4. **Comprehensive security** with multiple auth methods
5. **Declarative errors** via event-driven flow control
6. **Clean abstractions** through well-defined interfaces

The framework balances simplicity with power, providing sensible defaults while allowing customization at every level.
