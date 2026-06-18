// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/filters"
)

// home handler - returns an HTML page with forms to test both endpoints
func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Body Size Limit Example</title></head>
<body>
    <h1>Body Size Limit Example</h1>
    <p>This server enforces request body size limits:</p>
    <ul>
        <li><code>/api/data</code> &ndash; limited to <strong>1 KB</strong> (default limit)</li>
        <li><code>/upload</code> &ndash; limited to <strong>10 KB</strong> (path-specific limit)</li>
    </ul>

    <h2>Test /api/data (1 KB limit)</h2>
    <form id="dataForm">
        <textarea id="dataInput" rows="4" cols="60" placeholder="Enter JSON data here..."></textarea><br>
        <button type="submit">Send to /api/data</button>
        <span id="dataSize"></span>
    </form>
    <pre id="dataResult"></pre>

    <h2>Test /upload (10 KB limit)</h2>
    <form id="uploadForm">
        <textarea id="uploadInput" rows="4" cols="60" placeholder="Enter upload content here..."></textarea><br>
        <button type="submit">Send to /upload</button>
        <span id="uploadSize"></span>
    </form>
    <pre id="uploadResult"></pre>

    <h2>Try with curl</h2>
    <pre>
# Small payload (succeeds, within 1 KB limit)
curl -X POST -d '{"msg":"hello"}' http://localhost:8080/api/data

# Large payload (fails, exceeds 1 KB limit)
curl -X POST -d "$(python3 -c "print('x' * 2000)")" http://localhost:8080/api/data

# Upload within 10 KB limit (succeeds)
curl -X POST -d "$(python3 -c "print('x' * 5000)")" http://localhost:8080/upload

# Upload exceeding 10 KB limit (fails)
curl -X POST -d "$(python3 -c "print('x' * 20000)")" http://localhost:8080/upload
    </pre>

    <script>
    function updateSize(inputId, sizeId) {
        var el = document.getElementById(inputId);
        var sizeEl = document.getElementById(sizeId);
        el.addEventListener('input', function() {
            sizeEl.textContent = '(' + new Blob([el.value]).size + ' bytes)';
        });
    }
    updateSize('dataInput', 'dataSize');
    updateSize('uploadInput', 'uploadSize');

    function submitForm(formId, inputId, resultId, url) {
        document.getElementById(formId).addEventListener('submit', function(e) {
            e.preventDefault();
            var body = document.getElementById(inputId).value;
            fetch(url, { method: 'POST', body: body })
                .then(function(r) { return r.text().then(function(t) { return r.status + ' ' + r.statusText + '\n' + t; }); })
                .then(function(t) { document.getElementById(resultId).textContent = t; });
        });
    }
    submitForm('dataForm', 'dataInput', 'dataResult', '/api/data');
    submitForm('uploadForm', 'uploadInput', 'uploadResult', '/upload');
    </script>
</body>
</html>`)
	return nil
}

// handleData handles POST requests to /api/data.
// The body is limited to 1 KB by the body size limit filter.
func handleData(w http.ResponseWriter, scope we.RequestScope) error {
	body, err := io.ReadAll(scope.Request().Body)
	if err != nil {
		// MaxBytesReader returns an error when the limit is exceeded during read
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = fmt.Fprintf(w, "Error reading body: request body too large")
		return nil
	}
	defer scope.Request().Body.Close()

	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "Received %d bytes at /api/data\nContent: %s", len(body), string(body))
	return nil
}

// handleUpload handles POST requests to /upload.
// The body is limited to 10 KB by a path-specific size limit.
func handleUpload(w http.ResponseWriter, scope we.RequestScope) error {
	body, err := io.ReadAll(scope.Request().Body)
	if err != nil {
		// MaxBytesReader returns an error when the limit is exceeded during read
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = fmt.Fprintf(w, "Error reading body: request body too large")
		return nil
	}
	defer scope.Request().Body.Close()

	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "Received %d bytes at /upload\nContent length: %d bytes", len(body), len(body))
	return nil
}

func main() {
	// Create a body size limit filter with path-specific limits.
	//
	// - Default limit: 1 KB for all paths (small for easy testing;
	//   the framework default is filters.DefaultMaxBodySize = 10 MB).
	// - /upload: 10 KB (larger limit for file uploads).
	//
	// When a request body exceeds the configured limit, the filter
	// returns HTTP 413 Request Entity Too Large. It checks the
	// Content-Length header up front and also wraps the body with
	// http.MaxBytesReader to enforce the limit during reads.
	bodySizeFilter := filters.DefaultBodySizeLimit().
		MaxSize(1024).      // 1 KB default for all paths
		Path("/upload").    //
		MaxSize(10 * 1024). // 10 KB for uploads
		Build()

	// Build the engine with the body size limit filter and route handlers
	engine := we.New().
		Filter(bodySizeFilter).
		HandleMethod("GET", "/", home).
		HandleMethod("POST", "/api/data", handleData).
		HandleMethod("POST", "/upload", handleUpload).
		Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Body size limits:")
	fmt.Println("  /api/data  - 1 KB  (default limit)")
	fmt.Println("  /upload    - 10 KB (path-specific limit)")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
