// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gomatbase/go-we"
)

// example1 handler demonstrates how to capture a path variable from the URL and display it in the response.
func example1(w http.ResponseWriter, scope we.RequestScope) error {
	userId := scope.Var("id")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h2>User Profile</h2>
			<p>User ID: <strong>%s</strong></p>
			<p><a href="/">Back to examples</a></p>
		`, userId)
	return nil
}

// example2 handler demonstrates capturing multiple path variables from a more complex URL pattern and displaying
// them in the response.
func example2(w http.ResponseWriter, scope we.RequestScope) error {
	userId := scope.Var("userId")
	postId := scope.Var("postId")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h2>Post Details</h2>
			<p>User ID: <strong>%s</strong></p>
			<p>Post ID: <strong>%s</strong></p>
			<p><a href="/">Back to examples</a></p>
		`, userId, postId)
	return nil
}

// example3 handler demonstrates how to use a single wildcard in the URL pattern to capture a path segment and
// display it in the response. It also explains the matching behavior of the single wildcard.
func example3(w http.ResponseWriter, scope we.RequestScope) error {
	path := scope.Request().URL.Path
	filename := strings.TrimPrefix(path, "/files/")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h2>Single Wildcard Match</h2>
			<p>Requested file: <strong>%s</strong></p>
			<p>This pattern matches exactly one path segment after /files/</p>
			<p><a href="/">Back to examples</a></p>
		`, filename)
	return nil
}

// example4 handler demonstrates how to use a double wildcard in the URL pattern to capture multiple path segments
// and display the matched API path in the response. It also explains the matching behavior of the double wildcard.
func example4(w http.ResponseWriter, scope we.RequestScope) error {
	path := scope.Request().URL.Path
	apiPath := strings.TrimPrefix(path, "/api")
	if apiPath == "" {
		apiPath = "/"
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h2>Double Wildcard Match</h2>
			<p>API path: <strong>%s</strong></p>
			<p>This pattern matches any path under /api including /api itself</p>
			<p><a href="/">Back to examples</a></p>
		`, apiPath)
	return nil
}

// example5 handler demonstrates how to access query parameters from the URL, check for the presence of an optional
// parameter, and display the parameters in the response.
func example5(w http.ResponseWriter, scope we.RequestScope) error {
	query := scope.Parameter("q")
	page := scope.Parameter("page")

	// LookupParameter to check if parameter was sent
	category, hasCategory := scope.LookupParameter("category")

	w.Header().Set("Content-Type", "text/html")
	html := fmt.Sprintf(`
			<h2>Search Parameters</h2>
			<p>Query: <strong>%s</strong></p>
			<p>Page: <strong>%s</strong></p>
		`, query, page)

	if hasCategory {
		html += fmt.Sprintf(`<p>Category: <strong>%s</strong></p>`, category)
	} else {
		html += `<p>Category: <em>not specified</em></p>`
	}

	html += `<p><a href="/">Back to examples</a></p>`
	fmt.Fprint(w, html)
	return nil
}

// example6 handler demonstrates how to access multiple values for the same query parameter (e.g., ?tag=go&tag=web)
// and display all the values in the response.
func example6(w http.ResponseWriter, scope we.RequestScope) error {
	tags := scope.Parameters("tag")

	w.Header().Set("Content-Type", "text/html")
	html := `<h2>Multiple Parameter Values</h2>`

	if len(tags) > 0 {
		html += `<p>Tags:</p><ul>`
		for _, tag := range tags {
			html += fmt.Sprintf(`<li><strong>%s</strong></li>`, tag)
		}
		html += `</ul>`
	} else {
		html += `<p><em>No tags specified</em></p>`
	}

	html += `<p><a href="/">Back to examples</a></p>`
	fmt.Fprint(w, html)
	return nil
}

// example7a handler used together with example7b to demonstrate how exact path matches take precedence over variable
// patterns. It serves the /special/admin path and explains the precedence behavior in the response.
func example7a(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<h2>Exact Match Handler</h2>
			<p>This exact path <code>/special/admin</code> takes precedence over the variable pattern.</p>
			<p><a href="/">Back to examples</a></p>
		`)
	return nil
}

// example7b handler used together with example7a to demonstrate how variable path patterns are matched when there is
// no exact match. It captures the {page} variable from the URL and explains the precedence behavior in the response.
func example7b(w http.ResponseWriter, scope we.RequestScope) error {
	page := scope.Var("page")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h2>Variable Match Handler</h2>
			<p>Page: <strong>%s</strong></p>
			<p>Try visiting <a href="/special/admin">/special/admin</a> to see exact match precedence.</p>
			<p><a href="/">Back to examples</a></p>
		`, page)
	return nil
}

// home handler serves the main page with links to all the examples demonstrating path variables, wildcards, query
// parameters, and precedence. It provides an overview of the different URL patterns and how they are handled by the
// framework.
func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<h1>Path Variables & Wildcards Examples</h1>
			
			<h2>Path Variables</h2>
			<ul>
				<li><a href="/users/123">Single variable: /users/{id}</a></li>
				<li><a href="/users/456/posts/789">Multiple variables: /users/{userId}/posts/{postId}</a></li>
			</ul>

			<h2>Wildcards</h2>
			<ul>
				<li><a href="/files/document.pdf">Single wildcard (*): /files/*</a></li>
				<li><a href="/api">Double wildcard (**): /api/**</a></li>
				<li><a href="/api/v1/users">Double wildcard: /api/v1/users</a></li>
			</ul>

			<h2>Query Parameters</h2>
			<ul>
				<li><a href="/search?q=golang&page=2">Basic parameters: /search?q=golang&page=2</a></li>
				<li><a href="/search?q=golang&category=web">With optional parameter: /search?q=golang&category=web</a></li>
				<li><a href="/tags?tag=go&tag=web&tag=framework">Multiple values: /tags?tag=go&tag=web&tag=framework</a></li>
			</ul>

			<h2>Precedence</h2>
			<ul>
				<li><a href="/special/admin">Exact match: /special/admin</a> (takes precedence)</li>
				<li><a href="/special/settings">Variable match: /special/{page}</a></li>
			</ul>
		`)
	return nil
}

func main() {
	// create builder
	builder := we.New()

	// Example 1: Path variables - capture dynamic segments
	// URL pattern: /users/{id}
	// Example: /users/123 -> id = "123"
	builder.Handle("/users/{id}", example1)

	// Example 2: Multiple path variables
	// URL pattern: /users/{userId}/posts/{postId}
	builder.Handle("/users/{userId}/posts/{postId}", example2)

	// Example 3: Single wildcard (*) - matches exactly one segment
	// Matches: /files/document.pdf
	// Does NOT match: /files or /files/subfolder/document.pdf
	builder.Handle("/files/*", example3)

	// Example 4: Double wildcard (**) - matches zero or more segments
	// Matches: /api, /api/users, /api/v1/users, etc.
	builder.Handle("/api/**", example4)

	// Example 5: Query parameters
	// URL: /search?q=golang&page=2
	builder.Handle("/search", example5)

	// Example 6: Multiple parameter values
	// URL: /tags?tag=go&tag=web&tag=framework
	builder.Handle("/tags", example6)

	// Example 7: Precedence demonstration
	// Shows how exact matches take precedence over variables and wildcards
	builder.
		Handle("/special/admin", example7a).
		Handle("/special/{page}", example7b)

	// Home page with all examples
	builder.Handle("/", home)

	// create configured engine
	engine := builder.Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
