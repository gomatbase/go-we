# Basic Routing Example

This example demonstrates the fundamental routing capabilities of the go-we framework.

## What You'll Learn

- How to create a basic web server
- How to register GET and POST handlers
- How to handle form submissions
- How to send responses to clients

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

1. **GET Request**: Open your browser and visit `http://localhost:8080/`
   - You'll see a welcome message and an HTML form

2. **POST Request**: Submit the form with your name
   - The server will greet you personally

3. **Using curl**:
   ```bash
   # GET request
   curl http://localhost:8080/
   
   # POST request
   curl -X POST -d "name=Alice" http://localhost:8080/greet
   ```

## Key Concepts

### Creating a Server

```go
engine := we.New()
```

### Registering Handlers

**GET Handler:**
```go
engine.HandleMethod("GET", "/", func(w http.ResponseWriter, scope we.RequestScope) error {
    w.Write([]byte("Hello!"))
    return nil
})
```

**POST Handler:**
```go
engine.HandleMethod("POST", "/greet", func(w http.ResponseWriter, scope we.RequestScope) error {
    scope.Request().ParseForm()
    name := scope.Request().FormValue("name")
    // ... handle the form data
    return nil
})
```

### Starting the Server

```go
engine.Listen(":8080")
```

## Next Steps

- Move on to [02-path-variables](../02-path-variables/) to learn about dynamic routing
- See the [ARCHITECTURE](../../docs/ARCHITECTURE.md) documentation for deeper understanding
- Read [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) for production patterns
