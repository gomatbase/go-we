# go-we API Design Philosophy

This document explains the design decisions, philosophy, and rationale behind go-we's API design.

## Table of Contents

- [Design Principles](#design-principles)
- [Core API Decisions](#core-api-decisions)
- [Pattern Choices](#pattern-choices)
- [Trade-offs and Alternatives](#trade-offs-and-alternatives)
- [Evolution and Stability](#evolution-and-stability)

## Design Principles

### 1. Standard Library First

**Principle**: Build on top of Go's standard library, don't replace it.

go-we implements `http.Handler` and works seamlessly with `net/http`. This means:

```go
// Can be used with standard http.Server
engine := we.New().Build()
server := &http.Server{
    Addr:    ":8080",
    Handler: engine,
}
server.ListenAndServe()

// Or use go-we's convenience methods
engine := we.New().Build()
engine.Listen(":8080")
```

**Rationale**: 
- Developers already know `net/http`
- Easy migration from existing code
- Benefits from standard library improvements
- No lock-in to the framework

**What we avoid**: Creating our own HTTP server implementation, custom request/response types that hide standard library types.

### 2. Minimal Dependencies

**Principle**: Keep external dependencies to an absolute minimum.

go-we has **zero external dependencies** outside the Go standard library.

**Rationale**:
- Reduces security surface area
- Faster compilation
- No dependency version conflicts
- Easier auditing and compliance
- Smaller binary sizes

**Trade-off**: We implement some features ourselves (path tree, event system) rather than importing libraries. This means more maintenance but gives us full control and no external dependencies.

### 3. Type Safety Over Reflection

**Principle**: Leverage Go's type system for compile-time safety.

We use generics and strong typing rather than reflection:

```go
// Type-safe path tree using generics
type Tree[T any] interface {
    Add(path string, value T) error
    Get(path string) (T, map[string]string)
}

// Type-safe constants for security headers
type ReferrerPolicy string
const (
    ReferrerPolicyNoReferrer ReferrerPolicy = "no-referrer"
    ReferrerPolicyOrigin     ReferrerPolicy = "origin"
    // ...
)
```

**Rationale**:
- Errors caught at compile time
- Better IDE support and autocomplete
- No runtime type assertion failures
- Easier to understand and maintain

**What we avoid**: Using `interface{}` extensively, reflection for routing, string-based configuration with no validation.

### 4. Explicit Over Implicit

**Principle**: Make behavior obvious and predictable.

```go
// Explicit filter ordering
builder := we.New().
    Filter(corsFilter)       // Runs first
    Filter(securityFilter)   // Runs second
    Filter(loggingFilter)    // Runs third

// Explicit method routing
builder.HandleMethod("GET", "/users", listUsers)
    HandleMethod("POST", "/users", createUser)

// Explicit session configuration
builder.SessionManager(we.DefaultSessionManager().Build())

// Build the engine
engine := builder.Build()
```

**Rationale**:
- No magic or hidden behavior
- Easier to debug
- Code is self-documenting
- No surprising side effects

**What we avoid**: Auto-discovery of handlers, implicit ordering, convention-over-configuration where it hides behavior.

### 5. Flexibility Through Interfaces

**Principle**: Provide interfaces for customization points.

Key interfaces:
- `SessionStorage` - Custom session backends
- `AuthenticationProvider` - Custom auth methods
- `Authorization` - Custom authorization logic
- `ErrorHandler` - Custom error responses
- `Filter` - Custom middleware

**Rationale**:
- Users can replace any component
- Easy to integrate with existing systems
- Test with mock implementations
- Framework doesn't dictate architecture

**Example**: Database session storage

```go
type PostgresSessionStorage struct {
    db *sql.DB
}

func (s *PostgresSessionStorage) Get(ctx context.Context, id string) *Session {
    // Custom implementation
}

// Plug it in
sessionManager := we.DefaultSessionManager().
    Storage(&PostgresSessionStorage{db: db}).
    Build()

engine := we.New().
    SessionManager(sessionManager).
    Build()
```

## Core API Decisions

### Why Builder Pattern for Engine Creation

**Decision**: Use builder pattern to create and configure the engine.

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

**Rationale**:
1. **Fluent API** - Configuration reads naturally from top to bottom
2. **Type safety** - Builder methods enforce correct types and prevent invalid configurations
3. **Discoverability** - IDE autocomplete shows all available options
4. **Immutability** - Built engine is immutable and thread-safe
5. **Validation** - Can validate configuration at build time
6. **Flexibility** - Easy to add new configuration options without breaking changes
7. **Clarity** - Clear separation between configuration (builder) and runtime (engine)

**Alternative considered**: Direct struct initialization or setter methods
- **Rejected because**: 
  - Struct initialization requires exposing internal fields
  - Setter methods on engine would allow mutation after creation
  - No validation until first use
  - Less discoverable than builder pattern

**Example of builder benefits**:
```go
// Clear, fluent configuration
engine := we.New().
    Handle("/health", healthCheck).
    Filter(loggingFilter).
    SessionManager(we.DefaultSessionManager().
        SessionTimeout(2 * time.Hour).
        CookieSecure(true).
        Build()).
    Build()

// Engine is now immutable and ready to use
engine.Listen(":8080")
```

**Build-time validation**:
```go
// The builder can validate at build time
engine := we.New().
    ReadTimeout(-5 * time.Second). // PANIC: negative timeout not allowed
    Build()
```

### Why HandlerFunction Returns Error

**Decision**: Handlers return `error` instead of being void.

```go
type HandlerFunction func(http.ResponseWriter, RequestScope) error
```

**Rationale**:
1. **Declarative error handling** - Return errors directly instead of writing error responses
2. **Flow control** - Use events for redirects, interruptions
3. **Centralized error handling** - One place to format error responses
4. **Composability** - Easier to wrap and chain handlers

**Alternative considered**: `http.HandlerFunc` style (void return)
- **Rejected because**: Requires manual error response writing in every handler, no centralized error handling, harder to enforce consistent error formats.

**Example**:
```go
// With error return (go-we)
func getUser(w http.ResponseWriter, scope RequestScope) error {
    user, err := db.FindUser(scope.Var("id"))
    if err != nil {
        return events.NotFoundError // Declarative
    }
    return util.ReplyJson(w, user)
}

// Without error return (standard http)
func getUser(w http.ResponseWriter, r *http.Request) {
    user, err := db.FindUser(getID(r))
    if err != nil {
        w.WriteHeader(404) // Manual
        w.Write([]byte("Not found"))
        return
    }
    // ... manual JSON encoding
}
```

### Why RequestScope Interface

**Decision**: Abstract request context into `RequestScope` interface instead of passing `*http.Request` directly.

**Rationale**:
1. **Enhanced functionality** - Path variables, session access, attributes
2. **Testing** - Easy to mock without creating real HTTP requests
3. **Convenience** - Single source for variables, parameters, session

**Alternative considered**: Pass `*http.Request` and extract variables separately
- **Rejected because**: Forces users to manage variable extraction, session lookup, less convenient, harder to test.

**Example**:
```go
// With RequestScope (easier to test)
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    id := scope.Var("id")
    user := scope.Session().Get("user")
    // ...
}

// Mock in tests
scope := test.MockedRequestScope("GET", "http://localhost:8080/users/123")
handler(w, scope)
```

### Why Event-Driven Error Handling

**Decision**: Use `WeEvent` types for errors and flow control.

```go
type WeEvent interface {
    error
    StatusCode() int
    Payload() *Payload
    WithPayload(contentType string, content []byte) WeEvent
    WithAttribute(value string) WeEvent
}
```

**Rationale**:
1. **Semantic errors** - `NotFoundError`, `UnauthorizedError` are self-documenting
2. **Flow control** - Redirects and interruptions as events
3. **Immutability** - Events are immutable, safe for concurrent use
4. **Extensibility** - Add custom events, attach metadata

**Alternative considered**: Standard `error` with type assertions
- **Rejected because**: Less semantic, no built-in status codes, harder to attach metadata, more boilerplate.

**Example**:
```go
// Semantic and clean
if !authorized {
    return events.ForbiddenError
}

// With custom payload
if validationFailed {
    return events.BadRequestError.WithPayload(
        "application/json",
        []byte(`{"error":"validation_failed"}`),
    )
}

// Redirect
if needsLogin {
    return events.FoundRedirect.WithAttribute("/login")
}
```

### Why Separate Method-Specific Trees

**Decision**: Maintain separate path trees for each HTTP method.

**Rationale**:
1. **Performance** - No method checking during path matching
2. **Flexibility** - Different handlers for same path, different methods
3. **REST-friendly** - Natural fit for REST APIs
4. **Precedence** - Method-specific routes override "ALL" routes

**Alternative considered**: Single tree with method checking
- **Rejected because**: Slower (must check method on every match), less flexible, doesn't match REST patterns well.

**Example**:
```go
// Different handlers, same path
engine := we.New().
    HandleMethod("GET", "/users/{id}", getUser).
    HandleMethod("PUT", "/users/{id}", updateUser).
    HandleMethod("DELETE", "/users/{id}", deleteUser).
    Handle("/health", healthCheck). // Fallback for all methods
    Build()
```

### Why Builder Pattern for Configuration

**Decision**: Use fluent builder APIs for complex configuration (engine, filters, session manager, security).

```go
// Engine builder
engine := we.New().
    Handle("/", homeHandler).
    Filter(corsFilter).
    SessionManager(sessionManager).
    Build()

// CORS filter builder
corsFilter := filters.Cors().
    AllowedOrigins("https://example.com").
    AllowedMethods("GET", "POST").
    AllowCredentials().
    Path("/api/public/**").
        AllowedOrigins("*").
        Add().
    Build()

// Session manager builder
sessionManager := we.DefaultSessionManager().
    SessionTimeout(2 * time.Hour).
    CookieSecure(true).
    CookieSameSite(http.SameSiteStrictMode).
    Build()
```

**Rationale**:
1. **Readability** - Configuration reads like natural language
2. **Type safety** - Builder methods enforce valid configurations
3. **Discoverability** - IDE autocomplete guides developers
4. **Validation** - Can validate at build time (e.g., credentials + wildcard origins)
5. **Immutability** - Built object is immutable

**Alternative considered**: Struct-based configuration
- **Rejected because**: Less discoverable, no validation until runtime, harder to create complex nested configs.

**Example of build-time validation**:
```go
// This panics at build time (good!)
filters.Cors().
    AllowedOrigins("*").
    AllowCredentials(). // PANIC: Can't combine wildcard origins with credentials
    Build()
```

## Pattern Choices

### Filter Chain (Chain of Responsibility)

**Why this pattern**: Filters need to process requests in order with ability to short-circuit.

**Benefits**:
- Modular cross-cutting concerns
- Clear execution order
- Easy to add/remove filters
- Each filter can stop the chain

### Strategy Pattern for Pluggable Components

**Why this pattern**: Allow users to provide custom implementations.

**Where used**:
- `SessionStorage` - Different storage backends
- `AuthenticationProvider` - Different auth methods
- `Authorization` - Different authorization rules
- `ErrorHandler` - Different error formatting

**Benefits**:
- Framework doesn't dictate implementation
- Easy to test with mocks
- Can swap implementations per environment

### Trie for Path Matching

**Why this data structure**: Efficient matching with variables and wildcards.

**Benefits**:
- O(k) lookup where k = path depth
- Better than linear search for many routes
- Natural support for path variables
- Efficient wildcard matching

**Alternatives considered**:
- **Regex-based**: Slower, harder to debug, security risks
- **Linear search**: O(n) lookups, slow with many routes
- **Hash map**: Doesn't support variables/wildcards

### Immutable Events

**Why immutable**: Events can be reused safely across goroutines.

```go
// Base events are package constants
events.NotFoundError
events.BadRequestError

// WithPayload returns new instance
customError := events.BadRequestError.WithPayload("application/json", data)

// Original is unchanged
events.BadRequestError // Still has no payload
```

**Benefits**:
- Thread-safe by design
- Can reuse base events
- No accidental mutation
- Clear data flow

## Trade-offs and Alternatives

### Trade-off: No Dependency Injection Container

**Decision**: Don't provide a DI container.

**Rationale**: 
- Go favors explicit dependencies
- Containers add complexity
- Closures provide similar benefits

**Alternative approach**: Use closures for dependency injection

```go
func makeUserHandler(db *sql.DB, logger *log.Logger) we.HandlerFunction {
    return func(w http.ResponseWriter, scope we.RequestScope) error {
        // db and logger are in closure
        user, err := db.FindUser(scope.Var("id"))
        logger.Printf("Fetched user: %s", user.ID)
        // ...
    }
}

// Use it
engine := we.New().
    Handle("/users/{id}", makeUserHandler(db, logger)).
    Build()
```

### Trade-off: No Automatic Parameter Binding

**Decision**: Don't auto-bind request parameters to structs.

**Rationale**:
- Reflection is slow and error-prone
- Explicit code is clearer
- Type safety at compile time

**Alternative approach**: Use explicit JSON decoding

```go
// We provide utility functions
var req CreateUserRequest
if err := util.ReadJsonBody(scope.Request(), &req); err != nil {
    return events.BadRequestError
}
```

### Trade-off: No Built-in Validation

**Decision**: Don't include struct validation tags.

**Rationale**:
- Adds dependency
- Users can choose their own validator
- Validation logic should be explicit

**Alternative approach**: Integrate third-party validators as needed

```go
import "github.com/go-playground/validator/v10"

var validate = validator.New()

func createUser(w http.ResponseWriter, scope we.RequestScope) error {
    var req CreateUserRequest
    util.ReadJsonBody(scope.Request(), &req)
    
    if err := validate.Struct(&req); err != nil {
        return events.BadRequestError
    }
    // ...
}
```

### Trade-off: No Template Engine

**Decision**: Don't include HTML template rendering.

**Rationale**:
- Go's `html/template` is excellent
- Keeps framework focused
- Users can choose their preferred engine

**Alternative approach**: Use standard library or third-party templates

```go
import "html/template"

var templates = template.Must(template.ParseGlob("templates/*.html"))

func pageHandler(w http.ResponseWriter, scope we.RequestScope) error {
    data := map[string]interface{}{
        "User": scope.Session().Get("user"),
    }
    return templates.ExecuteTemplate(w, "page.html", data)
}
```

### Trade-off: Sessions Not Required

**Decision**: Sessions are opt-in, not enabled by default.

**Rationale**:
- Many APIs don't need sessions
- Avoids overhead when not needed
- Clear when sessions are active

**How to enable**:
```go
engine := we.New().
    SessionManager(we.DefaultSessionManager().Build()).
    Build()
```

## Evolution and Stability

### API Stability Guarantees

**v1.0.0 Promise**: The API is stable and follows semantic versioning.

- **Patch versions** (1.0.x): Bug fixes, no API changes
- **Minor versions** (1.x.0): New features, backward compatible
- **Major versions** (2.0.0): Breaking changes allowed

### Deprecation Policy

When deprecating APIs:
1. Mark as deprecated in godoc
2. Provide alternative in deprecation message
3. Keep for at least one minor version
4. Remove only in major version

Example:
```go
// Deprecated: Use Context() instead. Will be removed in v2.0.0.
func (rs *requestScope) GetContext() context.Context {
    return rs.Context()
}
```

### Backward Compatibility

We maintain backward compatibility within major versions:

- **Adding features**: Safe, won't break existing code
- **New interfaces**: Safe, existing implementations unaffected
- **New methods on interfaces**: Breaking, only in major versions
- **Changing signatures**: Breaking, only in major versions

### Extension Points

The framework provides extension points that won't break with updates:

- **Interfaces** - Implement for custom behavior
- **Events** - Create custom events
- **Filters** - Write custom filters
- **Builders** - Extend with custom builders

## Design Philosophy Summary

### What go-we Is

- **A foundation**: Build web apps on solid, simple base
- **Standard-library friendly**: Works with existing Go code
- **Opinionated but flexible**: Good defaults, but customizable
- **Production-ready**: Secure defaults, battle-tested patterns
- **Developer-friendly**: Clear APIs, good error messages

### What go-we Is Not

- **Not a full-stack framework**: No ORM, templates, frontend
- **Not Rails/Django**: No code generation, no magic
- **Not a microservices framework**: No service discovery, no distributed tracing built-in
- **Not enterprise-only**: Simple enough for small projects, powerful enough for large ones

### When to Use go-we

**Good fit**:
- REST APIs
- Traditional web applications with server-side rendering
- Microservices with HTTP endpoints
- Applications needing sessions and authentication
- Projects wanting more than `http.DefaultServeMux` without framework bloat

**Consider alternatives if**:
- You need GraphQL (use `graphql-go` or `gqlgen`)
- You need gRPC (use `grpc-go`)
- You want auto-generated CRUD (consider framework with ORM)
- You prefer convention over configuration (consider Beego, Buffalo)

## Design Influences

go-we draws inspiration from:

- **Go standard library** - Simple, composable, no magic
- **Servlet filters** (Java) - Filter chain pattern
- **Express.js** - Middleware pattern, routing
- **Spring Security** (Java) - Security filter configuration
- **JAX-RS** (Java) - Path variable syntax, method-specific routing

But adapted to Go's philosophy:
- Explicit over implicit
- Composition over inheritance
- Interfaces over frameworks
- Standard library over dependencies

## Contributing to Design

We welcome design discussions! When proposing API changes:

1. **Explain the problem** - What pain point are you solving?
2. **Show alternatives** - What other approaches exist?
3. **Consider trade-offs** - What are the downsides?
4. **Provide examples** - How would it be used?
5. **Think about stability** - Is it backward compatible?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

## Conclusion

go-we's design prioritizes:
- **Simplicity** - Easy to understand and use
- **Safety** - Type-safe, compile-time checks
- **Flexibility** - Customizable through interfaces
- **Standards** - Built on `net/http`, no reinventing
- **Stability** - Semantic versioning, backward compatibility

These principles guide all API decisions and will continue to shape the framework's evolution.
