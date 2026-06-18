# Rate Limiting Example

This example demonstrates how to use the built-in `filters.RateLimiter` to protect endpoints from excessive requests using the token bucket algorithm.

## What You'll Learn

- How to add a rate limiter filter to your server
- How to configure requests per second and burst size
- How to exempt specific paths (e.g., health checks) from rate limiting
- How the token bucket algorithm controls request throughput

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

1. **Normal request**: Open your browser and visit `http://localhost:8080/`
   - The first few requests succeed immediately (up to the burst size of 3)

2. **Trigger rate limiting**: Rapidly refresh the page
   - After the burst is exhausted, excess requests receive `429 Too Many Requests`

3. **Health check**: Visit `http://localhost:8080/health`
   - This endpoint is exempt from rate limiting and always responds

4. **Using curl**:
   ```bash
   # Send 10 rapid requests to see rate limiting in action
   for i in $(seq 1 10); do curl -w " HTTP %{http_code}\n" http://localhost:8080/; done

   # Health check is never throttled
   for i in $(seq 1 10); do curl -w " HTTP %{http_code}\n" http://localhost:8080/health; done

   # API endpoint is also rate limited
   curl http://localhost:8080/api/data
   ```

## Key Concepts

### Token Bucket Algorithm

The rate limiter uses the **token bucket** algorithm:

- A bucket holds up to `Burst` tokens (maximum capacity).
- Tokens are added at a rate of `RequestsPerSecond`.
- Each incoming request consumes one token.
- When the bucket is empty, requests are rejected with `429 Too Many Requests`.
- The burst allows short spikes above the sustained rate.

### Creating a Rate Limiter

```go
rateLimiter := filters.RateLimiter().
    RequestsPerSecond(2).      // Sustained rate: 2 requests per second
    Burst(3).                  // Allow bursts of up to 3 requests
    ExemptPaths("/health").    // Health checks bypass rate limiting
    Build()
```

### Adding the Filter to the Engine

```go
engine := we.New().
    Filter(rateLimiter).
    HandleMethod("GET", "/", home).
    HandleMethod("GET", "/api/data", apiData).
    HandleMethod("GET", "/health", healthCheck).
    Build()
```

### Custom Identifiers

By default, rate limiting is applied per client IP address. You can provide a custom identifier function to rate limit by a different key (e.g., API key or user ID):

```go
rateLimiter := filters.RateLimiter().
    RequestsPerSecond(10).
    Identifier(func(scope we.RequestScope) string {
        return scope.Request().Header.Get("X-API-Key")
    }).
    Build()
```

### Starting the Server

```go
engine.Listen(":8080")
```

## Next Steps

- See [04-custom-filters](../04-custom-filters/) for writing your own filters from scratch
- See [13-csrf-protection](../13-csrf-protection/) for another built-in filter example
- Read the [ARCHITECTURE](../../docs/ARCHITECTURE.md) documentation for deeper understanding
