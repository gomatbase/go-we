# Session Management Example

This example demonstrates how to use sessions in go-we to maintain stateful interactions with users.

## What You'll Learn

- How to configure and enable session management
- Storing and retrieving data from sessions
- Session lifecycle and timeouts
- Cookie configuration for security
- Login/logout patterns using sessions
- Session data persistence across requests

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

1. **Visit Counter**: Go to `http://localhost:8080/` - notice the visit counter increments on each page load
2. **Login**: Click "Login" and enter a username - your session will remember you
3. **Profile**: View your profile to see session data
4. **Preferences**: Set and view theme preferences stored in your session
5. **Logout**: Remove authentication data while keeping the session active
6. **Clear Session**: Remove all session data

## Key Concepts

### Configuring the default Session Manager with default storage (in-memory):

Use the builder pattern to configure the session manager:

```go
sessionManager := we.DefaultSessionManager().
    SessionTimeout(30 * time.Minute).         // Session expires after 30 min inactivity
    CookieName("go_we_session").              // Custom cookie name
    CookieSecure(false).                      // Use true in production (HTTPS only)
    CookieSameSite(http.SameSiteLaxMode).     // CSRF protection
    CookieHttpOnly(true).                     // Prevent XSS (JavaScript can't access)
    SessionPurgingInterval(5 * time.Minute).  // Cleanup frequency
    Build()

engine.SetSessionManager(sessionManager)
```

### Storing Data in Sessions

```go
// Store any value in the session
scope.SetInSession("username", "alice")
scope.SetInSession("login_time", time.Now())
scope.SetInSession("visit_count", 42)

// Store complex types (maps, structs, etc.)
scope.SetInSession("user_preferences", map[string]string{
    "theme": "dark",
    "language": "en",
})
```

### Retrieving Data from Sessions

```go
// Get value from session (returns any or nil)
username := scope.GetFromSession("username")

// Check if value exists
if username != nil {
    // Type assert to use the value
    name := username.(string)
    fmt.Println("Welcome,", name)
}
```

### Removing Data from Sessions

```go
// Remove a specific key by setting it to nil
scope.SetInSession("username", nil)
scope.SetInSession("login_time", nil)
```

### Session Lifecycle

**Session Creation:**
- Sessions are created automatically on first request when SessionManager is configured
- Each session gets a unique ID stored in a cookie

**Session Timeout:**
```go
SessionTimeout(30 * time.Minute)  // Rolling timeout (default)
```
- **Rolling Sessions** (default): Timeout resets on each request
- **Static Sessions**: Fixed expiration from creation time

```go
sessionManager := we.DefaultSessionManager().
    SessionTimeout(1 * time.Hour).
    StaticSessionLifespan(true).  // Session expires exactly 1 hour after creation
    Build()
```

**Session Cleanup:**
```go
SessionPurgingInterval(5 * time.Minute)  // Check for expired sessions every 5 min
```

## Cookie Security Configuration

### HttpOnly (XSS Protection)

```go
CookieHttpOnly(true)  // JavaScript cannot access the cookie
```

**Recommendation:** Always `true` unless you specifically need JavaScript access.

### Secure (HTTPS Only)

```go
CookieSecure(true)  // Cookie only sent over HTTPS
```

**Recommendation:** `true` in production, `false` in development.

### SameSite (CSRF Protection)

```go
CookieSameSite(http.SameSiteLaxMode)   // Good balance
CookieSameSite(http.SameSiteStrictMode) // Maximum protection
CookieSameSite(http.SameSiteNoneMode)   // Cross-site allowed (requires Secure)
```

**SameSite Modes:**
- **Strict**: Cookie never sent in cross-site requests (even following a link)
- **Lax**: Cookie sent when user navigates to your site (default, good balance)
- **None**: Cookie sent in all contexts (requires `Secure=true`)

### Cookie Scope

```go
CookiePath("/")              // Cookie available on all paths
CookiePath("/admin")         // Cookie only for /admin/* paths

CookieDomain("")             // Current domain only (default)
CookieDomain("example.com")  // All subdomains of example.com
```

### Cookie Lifetime

```go
CookieMaxAge(0)      // Session cookie (deleted when browser closes) - default
CookieMaxAge(3600)   // Cookie persists for 1 hour even after browser closes
CookieMaxAge(-1)     // Delete cookie immediately
```

## Common Patterns

### Login Pattern

```go
builder.HandleMethod("POST", "/login", func(w http.ResponseWriter, scope we.RequestScope) error {
    // Validate credentials (simplified for example)
    username := scope.Request().FormValue("username")
    
    // Store in session
    scope.SetInSession("username", username)
    scope.SetInSession("login_time", time.Now())
    
    http.Redirect(w, scope.Request(), "/dashboard", http.StatusSeeOther)
    return nil
})
```

### Protected Routes

```go
builder.Handle("/profile", func(w http.ResponseWriter, scope we.RequestScope) error {
    username := scope.GetFromSession("username")
    if username == nil {
        // Not logged in - redirect to login
        http.Redirect(w, scope.Request(), "/login", http.StatusSeeOther)
        return nil
    }
    
    // User is logged in - show profile
    // ...
    return nil
})
```

### Logout Pattern

```go
builder.Handle("/logout", func(w http.ResponseWriter, scope we.RequestScope) error {
    // Remove authentication data
    scope.SetInSession("username", nil)
    scope.SetInSession("login_time", nil)
    
    http.Redirect(w, scope.Request(), "/", http.StatusSeeOther)
    return nil
})
```

## Session Storage

By default, sessions are stored in memory. For production with multiple servers, use custom storage:

```go
// Implement SessionStorage interface for Redis, database, etc.
type RedisStorage struct {
    // ... your implementation
}

sessionManager := we.DefaultSessionManager().
    Storage(redisStorage).  // Custom storage
    Build()
```

## Best Practices

1. **Always use HTTPS in production** with `CookieSecure(true)`
2. **Keep HttpOnly enabled** to prevent XSS attacks
3. **Use SameSite=Lax or Strict** for CSRF protection
4. **Set appropriate timeouts** - balance security vs. user experience
5. **Don't store sensitive data** in sessions without encryption
6. **Use rolling sessions** for better UX (default behavior)
7. **Configure cleanup interval** based on your traffic and timeout settings
8. **Implement proper logout** by clearing authentication data

## Session vs. Cookie

**Session (server-side):**
- Stores actual data on the server
- Client only gets a session ID cookie
- More secure for sensitive data
- Can store any data type

**Cookie (client-side):**
- Data stored in the browser
- Sent with every request
- Size limited (4KB typically)
- Should not contain sensitive data

Go-We uses cookies to store the **session ID only**. All session data stays on the server.

## Session Storage

By default, the default session manager uses in-memory storage, which is not suitable for multi-instance deployments
nor production environments if restart/crash resilience is required. For production, implement the `SessionStorage` 
interface to use some kind of persistent store.

## Default Session Manager

The default session manager provides a convenient way to get started with sessions. It uses in-memory storage by default
and has sensible defaults for cookie configuration and session lifecycle.

It can be configured with a custom production-ready storage implementation and is suitable for production environments.

## Next Steps

- Move on to [04-custom-filters](../04-custom-filters/) to learn about middleware
- See [05-basic-auth](../05-basic-auth/) for authentication examples
- Read [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) for session security patterns
