# Static File Serving Example

Demonstrates serving static files (HTML, CSS, JavaScript, images, etc.) using go-we.

## Running

```bash
go run main.go
```

The example automatically creates sample static files in `./static/` directory.

## Try It

- `/static/index.html` - Sample HTML page
- `/static/style.css` - CSS stylesheet
- `/static/script.js` - JavaScript file
- `/static/sample.txt` - Text file

## How It Works

### Basic Static File Serving

Using standard library file serving utilities with plain handler conversion

```go
fileServer := http.FileServer(http.Dir("./static"))
handler := http.StripPrefix("/static/", fileServer)

builder.Handle("/static/**", convert.Handler(handler))
```

### With Custom Headers

Encapsulating standard library file serving utilities with a we.HandlerFunction to add custom behaviour.

```go

fileServer := http.FileServer(http.Dir("./static"))
handler := http.StripPrefix("/assets/", fileServer)

builder.Handle("/assets/**", func(w http.ResponseWriter, scope we.RequestScope) error {
    // Add cache headers
    w.Header().Set("Cache-Control", "public, max-age=31536000") // 1 year
    
    handler.ServeHTTP(w, scope.Request())
    return nil
    })
```

## Best Practices

1. **Use CDN in production** for better performance
2. **Set cache headers** for static assets
3. **Version your assets** (e.g., `/static/v1.2.3/app.js`)
4. **Compress files** (gzip/brotli) for smaller transfers
5. **Disable directory listing** in production
6. **Serve from different domain** to avoid cookie overhead

## Cache Headers

```go
// Long cache for versioned assets
w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

// No cache for HTML (allows updates)
w.Header().Set("Cache-Control", "no-cache")

// Short cache for frequently updated files
w.Header().Set("Cache-Control", "public, max-age=3600")
```

## Security

- Don't serve files outside intended directory
- Validate file paths to prevent directory traversal
- Set appropriate MIME types
- Use HTTPS in production
- Consider setting CSP headers

## Next Steps

- [12-full-application](../12-full-application/) - Complete application example
- [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) - Production best practices
