// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
)

func main() {
	// Create a new web engine
	engine := we.New()

	// GET handler for root path - displays a simple HTML page with links and a form
	engine.HandleMethod("GET", "/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
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
	})

	// GET handler for /hello - returns a plain text greeting
	engine.HandleMethod("GET", "/hello", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from Go-We!")
		return nil
	})

	// GET handler for /about - returns information about the framework
	engine.HandleMethod("GET", "/about", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Go-We is a lightweight web framework for Go")
		return nil
	})

	// POST handler for /submit - handles form submission
	engine.HandleMethod("POST", "/submit", func(w http.ResponseWriter, scope we.RequestScope) error {
		// Parse form data from the request
		scope.Request().ParseForm()
		message := scope.Request().FormValue("message")

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>Form Submitted!</h1>
			<p>Your message: <strong>%s</strong></p>
			<p><a href="/">Go back</a></p>
		`, message)
		return nil
	})

	// Start the server on port 8080
	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
