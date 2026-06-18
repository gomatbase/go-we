# Body Size Limit Example

This example demonstrates how to use the built-in `filters.BodySizeLimit` filter to enforce maximum request body sizes, protecting your server from oversized payloads and denial-of-service attacks.

## What You'll Learn

- How to add a body size limit filter to your server
- How to set a default maximum body size for all paths
- How to configure path-specific size limits for different endpoints
- How the filter rejects oversized requests with HTTP 413

## Running the Example

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## Try It Out

1. **Home page**: Open your browser and visit `http://localhost:8080/`
   - You'll see an HTML page with forms to test both endpoints

2. **Small payload to /api/data**: Submit a short JSON string
   - Succeeds because the body is within the 1 KB default limit

3. **Large payload to /api/data**: Submit more than 1 KB of data
   - Fails with `413 Request Entity Too Large`

4. **Upload to /upload**: Submit up to 10 KB of data
   - Succeeds because /upload has a higher path-specific limit

5. **Using curl**:
   ```bash
   # Small payload (succeeds, within 1 KB limit)
   curl -X POST -d '{"msg":"hello"}' http://localhost:8080/api/data

   # Large payload (fails, exceeds 1 KB limit)
   curl -X POST -d "$(python3 -c "print('x' * 2000)")" http://localhost:8080/api/data

   # Upload within 10 KB limit (succeeds)
   curl -X POST -d "$(python3 -c "print('x' * 5000)")" http://localhost:8080/upload

   # Upload exceeding 10 KB limit (fails)
   curl -X POST -d "$(python3 -c "print('x' * 20000)")" http://localhost:8080/upload
   ```

## Key Concepts

### How Body Size Limiting Works

The filter enforces size limits in two ways:

1. **Content-Length check**: If the `Content-Length` header exceeds the limit, the request is immediately rejected with HTTP 413.
2. **MaxBytesReader wrapping**: The request body is wrapped with `http.MaxBytesReader`, which enforces the limit during actual reads. This catches chunked transfers and requests without `Content-Length`.

### Creating a Body Size Limit Filter

```go
bodySizeFilter := filters.DefaultBodySizeLimit().
    MaxSize(1024).            // 1 KB default for all paths
    Path("/upload").          // configure path-specific limit
        MaxSize(10 * 1024).   // 10 KB for uploads
    Build()
```

The framework default (`filters.DefaultMaxBodySize`) is 10 MB. Call `MaxSize()` on the builder to override the default for all paths.

### Path-Specific Limits

Use `Path()` to set different limits for specific endpoints:

```go
filter := filters.DefaultBodySizeLimit().
    MaxSize(1024 * 1024).            // 1 MB default
    Path("/api/upload").
        MaxSize(10 * 1024 * 1024).   // 10 MB for uploads
    Path("/api/import").
        MaxSize(50 * 1024 * 1024).   // 50 MB for imports
    Build()
```

### Adding the Filter to the Engine

```go
engine := we.New().
    Filter(bodySizeFilter).
    HandleMethod("POST", "/api/data", handleData).
    HandleMethod("POST", "/upload", handleUpload).
    Build()
```

### Starting the Server

```go
engine.Listen(":8080")
```

## Next Steps

- See [14-rate-limiting](../14-rate-limiting/) for another built-in filter example
- See [04-custom-filters](../04-custom-filters/) for writing your own filters from scratch
- Read the [ARCHITECTURE](../../docs/ARCHITECTURE.md) documentation for deeper understanding
