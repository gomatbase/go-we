// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gomatbase/go-we"
)

func main() {
	engine := we.New()

	// Example 1: Path variables - capture dynamic segments
	// URL pattern: /users/{id}
	// Example: /users/123 -> id = "123"
	engine.Handle("/users/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
		userId := scope.Var("id")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h2>User Profile</h2>
			<p>User ID: <strong>%s</strong></p>
			<p><a href="/">Back to examples</a></p>
		`, userId)
		return nil
	})

	// Example 2: Multiple path variables
	// URL pattern: /users/{userId}/posts/{postId}
	engine.Handle("/users/{userId}/posts/{postId}", func(w http.ResponseWriter, scope we.RequestScope) error {
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
	})

	// Example 3: Single wildcard (*) - matches exactly one segment
	// Matches: /files/document.pdf
	// Does NOT match: /files or /files/subfolder/document.pdf
	engine.Handle("/files/*", func(w http.ResponseWriter, scope we.RequestScope) error {
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
	})

	// Example 4: Double wildcard (**) - matches zero or more segments
	// Matches: /api, /api/users, /api/v1/users, etc.
	engine.Handle("/api/**", func(w http.ResponseWriter, scope we.RequestScope) error {
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
	})

	// Example 5: Query parameters
	// URL: /search?q=golang&page=2
	engine.Handle("/search", func(w http.ResponseWriter, scope we.RequestScope) error {
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
	})

	// Example 6: Multiple parameter values
	// URL: /tags?tag=go&tag=web&tag=framework
	engine.Handle("/tags", func(w http.ResponseWriter, scope we.RequestScope) error {
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
	})

	// Example 7: Precedence demonstration
	// Shows how exact matches take precedence over variables and wildcards
	engine.Handle("/special/admin", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h2>Exact Match Handler</h2>
			<p>This exact path <code>/special/admin</code> takes precedence over the variable pattern.</p>
			<p><a href="/">Back to examples</a></p>
		`)
		return nil
	})

	engine.Handle("/special/{page}", func(w http.ResponseWriter, scope we.RequestScope) error {
		page := scope.Var("page")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h2>Variable Match Handler</h2>
			<p>Page: <strong>%s</strong></p>
			<p>Try visiting <a href="/special/admin">/special/admin</a> to see exact match precedence.</p>
			<p><a href="/">Back to examples</a></p>
		`, page)
		return nil
	})

	// Home page with all examples
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
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
	})

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
