# Error Handling Example

Demonstrates error handling with WeEvent errors and custom error responses.

## Running

```bash
go run main.go
```

## Try It

Visit `http://localhost:8080/` to see all error scenarios with clickable links.

```bash
# Test different error codes
curl http://localhost:8080/error/404 -v
curl http://localhost:8080/error/401 -v
curl http://localhost:8080/error/500 -v

# Custom error with message
curl http://localhost:8080/error/custom -v

# Custom error with JSON payload
curl http://localhost:8080/error/payload -v

# Handled panic
curl http://localhost:8080/error/panic -v
```

## Key Concepts

### Built-in Error Events

```go
return events.BadRequestError        // 400
return events.UnauthorizedError      // 401
return events.ForbiddenError         // 403
return events.NotFoundError          // 404
return events.InternalServerError    // 500
```

### Custom Errors

**Simple error:**
```go
return events.New(418, "I'm a teapot")
```

**Error with JSON payload:**
```go
jsonPayload := `{"error": "validation failed"}`
return events.NewPayload(422, "Validation failed", &events.Payload{
    ContentTypeHint: "application/json",
    Content:         []byte(jsonPayload),
})
```

### Conditional Errors

```go
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    email := scope.Parameter("email")
    
    if email == "" {
        return events.New(400, "Email parameter is required")
    }
    
    // Process request...
    return nil
}
```

### Panic Recovery

The framework automatically catches panics in handlers:

```go
func handler(w http.ResponseWriter, scope we.RequestScope) error {
    panic("Something went wrong!")
    // Framework catches this and returns 500 error
}
```

## Error Response Flow

1. Handler returns error
2. Framework checks if it's a `WeEvent`
3. Extracts status code and payload
4. Sends HTTP response with appropriate status
5. If payload exists, sends it as response body

## Next Steps

- [12-rest-api](../12-rest-api/) - REST API with JSON
- [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) - Error handling patterns
