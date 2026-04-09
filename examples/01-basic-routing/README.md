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

### Creating Handlers

**Simple output Handler:**
```go
func hello(w http.ResponseWriter, scope we.RequestScope) error {
   w.Header().Set("Content-Type", "text/plain")
   _, _ = fmt.Fprintf(w, "Hello from Go-We!")
   return nil
}
```

**Content processing Handler:**
```go
func processForm(w http.ResponseWriter, scope we.RequestScope) error {
   // Parse form data from the request
   _ = scope.Request().ParseForm()
   message := scope.Request().FormValue("message")
   
   w.Header().Set("Content-Type", "text/html")
   _, _ = fmt.Fprintf(w, `
               <h1>Form Submitted!</h1>
               <p>Your message: <strong>%s</strong></p>
               <p><a href="/">Go back</a></p>
           `, message)
   return nil
}
```

### Creating an engine through a builder

```go
engine := we.New().
   HandleMethod("GET", "/", home). // GET handler for root path
   HandleMethod("GET", "/hello", hello). // GET handler for /hello
   HandleMethod("GET", "/about", about). // GET handler for /about
   HandleMethod("POST", "/submit", processForm). // POST handler for /submit - handles form submission
   Build() // and build the configured engine
```

### Registering Handlers

**GET Handler:**
```go
   HandleMethod("GET", "/", home). // GET handler for root path
```

**POST Handler:**
```go
   HandleMethod("POST", "/submit", processForm). // POST handler for /submit - handles form submission
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
