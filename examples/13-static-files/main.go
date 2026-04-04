// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gomatbase/go-we"
)

func main() {
	engine := we.New()

	// Create static files directory and sample files
	setupStaticFiles()

	// Home page
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Static File Serving Example</h1>
			
			<h2>Try It</h2>
			<ul>
				<li><a href="/static/index.html">Static HTML Page</a></li>
				<li><a href="/static/style.css">CSS File</a></li>
				<li><a href="/static/script.js">JavaScript File</a></li>
				<li><a href="/static/sample.txt">Text File</a></li>
			</ul>

			<h2>How It Works</h2>
			<p>Static files are served using <code>http.FileServer</code> wrapped in a handler:</p>
			<pre>
fileServer := http.FileServer(http.Dir("./static"))
engine.Handle("/static/**", func(w http.ResponseWriter, scope we.RequestScope) error {
    http.StripPrefix("/static/", fileServer).ServeHTTP(w, scope.Request())
    return nil
})
			</pre>

			<h2>Key Features</h2>
			<ul>
				<li>Automatic MIME type detection</li>
				<li>Directory listing (if enabled)</li>
				<li>Range requests (partial content)</li>
				<li>ETag support for caching</li>
				<li>Compression (if configured)</li>
			</ul>
		`)
		return nil
	})

	// Serve static files from ./static directory
	fileServer := http.FileServer(http.Dir("./static"))

	engine.Handle("/static/**", func(w http.ResponseWriter, scope we.RequestScope) error {
		// Strip /static prefix and serve
		http.StripPrefix("/static/", fileServer).ServeHTTP(w, scope.Request())
		return nil
	})

	// Alternative: Serve files with custom caching headers
	engine.Handle("/assets/**", func(w http.ResponseWriter, scope we.RequestScope) error {
		// Add cache headers
		w.Header().Set("Cache-Control", "public, max-age=31536000") // 1 year

		fs := http.FileServer(http.Dir("./static"))
		http.StripPrefix("/assets/", fs).ServeHTTP(w, scope.Request())
		return nil
	})

	log.Println("Server starting on http://localhost:8080")
	log.Println("Serving static files from ./static directory")
	log.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}

// setupStaticFiles creates sample static files for demonstration
func setupStaticFiles() {
	// Create static directory
	os.MkdirAll("./static", 0755)

	// Create sample HTML file
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <title>Static HTML Page</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>Hello from Static HTML!</h1>
    <p>This file is served from the ./static directory.</p>
    <p><a href="/">Back to home</a></p>
    <script src="/static/script.js"></script>
</body>
</html>`
	os.WriteFile("./static/index.html", []byte(htmlContent), 0644)

	// Create sample CSS file
	cssContent := `body {
    font-family: Arial, sans-serif;
    max-width: 800px;
    margin: 50px auto;
    padding: 20px;
    background-color: #f5f5f5;
}

h1 {
    color: #333;
}`
	os.WriteFile("./static/style.css", []byte(cssContent), 0644)

	// Create sample JavaScript file
	jsContent := `console.log('JavaScript file loaded successfully!');

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM ready!');
});`
	os.WriteFile("./static/script.js", []byte(jsContent), 0644)

	// Create sample text file
	txtContent := `This is a sample text file.
It demonstrates serving plain text files.

Static file serving supports:
- Automatic MIME type detection
- Caching headers
- Range requests
- Directory listings (if enabled)`
	os.WriteFile("./static/sample.txt", []byte(txtContent), 0644)

	log.Println("Created sample static files in ./static directory")
}
