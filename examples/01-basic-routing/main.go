// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
)

// home handler - displays a simple HTML page with links and a form
func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, `
			<h1>Welcome to Go-We!</h1>
			<p>This is a basic routing example.</p>
			<ul>
				<li><a href="/">Home (GET)</a></li>
				<li><a href="/hello">Hello (GET)</a></li>
				<li><a href="/about">About (GET)</a></li>
			</ul>
			<form action="/submit" method="POST">
				<input type="text" name="message" placeholder="Enter a message">
				<button type="submit">Submit (POST)</button>
			</form>
		`)
	return nil
}

// hello handler - returns a plain text greeting
func hello(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "Hello from Go-We!")
	return nil
}

// about handler - returns information about the framework
func about(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "Go-We is a lightweight web framework for Go")
	return nil
}

// processForm handler - handles form submission
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

func main() {
	// Create a new web engine builder and define routes and handlers
	engine := we.New().
		HandleMethod("GET", "/", home).               // GET handler for root path
		HandleMethod("GET", "/hello", hello).         // GET handler for /hello
		HandleMethod("GET", "/about", about).         // GET handler for /about
		HandleMethod("POST", "/submit", processForm). // POST handler for /submit - handles form submission
		Build()                                       // and build the configured engine

	// Start the server on port 8080
	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
