# Path Variables & Wildcards Example

This example demonstrates dynamic routing with path variables, wildcards, and query parameters in go-we.

## What You'll Learn

- How to use path variables to capture URL segments
- Single wildcard (`*`) vs. double wildcard (`**`) matching
- Working with query parameters
- Understanding route precedence (exact > variables > wildcards)
- Handling multiple parameter values

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

Visit `http://localhost:8080/` to see all available examples with clickable links.

### Path Variables

```bash
# Single variable
curl http://localhost:8080/users/123

# Multiple variables
curl http://localhost:8080/users/456/posts/789
```

### Wildcards

```bash
# Single wildcard - matches exactly one segment
curl http://localhost:8080/files/document.pdf

# Double wildcard - matches any remaining path
curl http://localhost:8080/api
curl http://localhost:8080/api/v1/users
```

### Query Parameters

```bash
# Basic parameters
curl "http://localhost:8080/search?q=golang&page=2"

# Multiple values for the same parameter
curl "http://localhost:8080/tags?tag=go&tag=web&tag=framework"
```

## Key Concepts

### Path Variables

Path variables are defined using curly braces `{name}`:

```go
builder.Handle("/users/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
    userId := scope.Var("id")  // Extract the variable
    // ...
    return nil
})
```

You can have multiple variables in one path:

```go
builder.Handle("/users/{userId}/posts/{postId}", handler)
```

### Wildcards

**Single Wildcard (`*`):**
- Matches **exactly one** path segment
- `/files/*` matches `/files/doc.pdf` but NOT `/files` or `/files/sub/doc.pdf`

**Double Wildcard (`**`):**
- Matches **zero or more** remaining segments
- `/api/**` matches `/api`, `/api/users`, `/api/v1/users`, etc.

### Query Parameters

```go
// Get single parameter value
query := scope.Parameter("q")

// Check if parameter exists
category, exists := scope.LookupParameter("category")

// Get multiple values for same parameter
tags := scope.Parameters("tag")  // Returns []string
```

### Route Precedence

When multiple routes could match a request, go-we uses this priority:

1. **Exact paths** - `/users/admin` (highest priority)
2. **Path variables** - `/users/{id}`
3. **Single wildcard** - `/users/*`
4. **Double wildcard** - `/users/**` (lowest priority)

**Example:**

```go
builder.Handle("/special/admin", exactHandler)    // Exact
builder.Handle("/special/{page}", variableHandler) // Variable

// GET /special/admin -> exactHandler (exact match wins)
// GET /special/settings -> variableHandler (variable matches)
```

## Wildcard Behavior Details

### Single Wildcard (`*`)

```go
builder.Handle("/files/*", handler)

// Matches:     /files/document.pdf
// Does NOT match:  /files
// Does NOT match:  /files/subfolder/document.pdf
```

### Double Wildcard (`**`)

```go
builder.Handle("/api/**", handler)

// Matches:     /api
// Matches:     /api/users
// Matches:     /api/v1/users
// Matches:     /api/v1/users/123/posts
```

## Next Steps

- Move on to [03-session-management](../03-session-management/) to learn about stateful applications
- See [ARCHITECTURE](../../docs/ARCHITECTURE.md) for deep dive into the path tree algorithm
- Read [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) for routing patterns in production
