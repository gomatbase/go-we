# CSRF Protection Example

This example demonstrates how to use the CSRF (Cross-Site Request Forgery) protection filter in the go-we framework.

## What You'll Learn

- How to configure the CSRF filter
- How to embed CSRF tokens in HTML forms
- How to exempt specific paths from CSRF validation
- How CSRF tokens are stored and validated via sessions

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

1. **Submit the form**: Open `http://localhost:8080/` in your browser and submit the form. The CSRF token is included as a hidden field and validated on the server.

2. **POST without a token** (rejected):
   ```bash
   curl -X POST -d "message=hello" http://localhost:8080/submit
   ```

3. **Exempt endpoint** (no token required):
   ```bash
   curl -X POST -d '{"event":"test"}' http://localhost:8080/api/webhook
   ```

## Key Concepts

### Configuring the CSRF Filter

```go
csrfFilter := filters.Csrf().
    ExemptPaths("/api/webhook").  // Paths that bypass CSRF validation
    Build()
```

### Embedding the Token in a Form

The CSRF filter generates a token on GET requests and stores it in the session. Retrieve it and include it as a hidden field:

```go
token := scope.Session().Get("_csrf_token")
fmt.Fprintf(w, `<input type="hidden" name="_csrf" value="%s">`, token)
```

### How Validation Works

- **Safe methods** (GET, HEAD, OPTIONS): A token is auto-generated in the session if one does not exist.
- **State-changing methods** (POST, PUT, DELETE, PATCH): The filter checks for a valid token in the `X-CSRF-Token` header or the `_csrf` form field. Requests without a valid token are rejected with 403 Forbidden.

### Wiring It Together

```go
engine := we.New().
    SessionManager(we.DefaultSessionManager().Build()).
    Filter(csrfFilter).
    HandleMethod("GET", "/", home).
    HandleMethod("POST", "/submit", submitForm).
    Build()
```

## Next Steps

- See [03-session-management](../03-session-management/) for session configuration options
- See [04-custom-filters](../04-custom-filters/) for writing your own filters
