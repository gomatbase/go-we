// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/security"
)

func main() {
	engine := we.New()

	// Define users with different scopes
	users := []security.User{
		{Username: "admin", Password: "admin123", Scopes: []string{"admin", "editor", "viewer"}},
		{Username: "editor", Password: "editor123", Scopes: []string{"editor", "viewer"}},
		{Username: "viewer", Password: "viewer123", Scopes: []string{"viewer"}},
		{Username: "guest", Password: "guest123", Scopes: []string{}},
	}

	// Create authentication provider
	authProvider := security.BasicAuthenticationProvider(users...).Build()

	// Configure authorization with Role-Based Access Control (RBAC)
	securityFilter := security.Filter(false).
		// Public endpoints
		Path("/", "/public/**").
		Anonymous().
		// Viewer role - read-only access
		Path("/view/**").
		Authentication(authProvider).
		Authorize(security.Scope("viewer")).
		// Editor role - create and update
		Path("/edit/**").
		Authentication(authProvider).
		Authorize(security.Scope("editor")).
		// Admin role - full access
		Path("/admin/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		// API with multiple authorization rules
		Path("/api/public/**").
		Anonymous().
		// API read requires viewer scope
		Path("/api/read/**").
		Authentication(authProvider).
		Authorize(security.Scope("viewer")).
		// API write requires editor OR admin scope
		Path("/api/write/**").
		Authentication(authProvider).
		Authorize(security.Either(
			security.Scope("editor"),
			security.Scope("admin"),
		)).
		// API delete requires admin scope
		Path("/api/delete/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		Build()

	engine.AddFilter(securityFilter)

	// Home page with authorization matrix
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Authorization & RBAC Example</h1>
			
			<h2>User Roles & Scopes</h2>
			<table border="1" cellpadding="10">
				<tr>
					<th>Username</th>
					<th>Password</th>
					<th>Scopes</th>
				</tr>
				<tr>
					<td>admin</td>
					<td>admin123</td>
					<td>admin, editor, viewer</td>
				</tr>
				<tr>
					<td>editor</td>
					<td>editor123</td>
					<td>editor, viewer</td>
				</tr>
				<tr>
					<td>viewer</td>
					<td>viewer123</td>
					<td>viewer</td>
				</tr>
				<tr>
					<td>guest</td>
					<td>guest123</td>
					<td>(none)</td>
				</tr>
			</table>

			<h2>Access Control Matrix</h2>
			<table border="1" cellpadding="10">
				<tr>
					<th>Endpoint</th>
					<th>Required Scope</th>
					<th>admin</th>
					<th>editor</th>
					<th>viewer</th>
					<th>guest</th>
				</tr>
				<tr>
					<td>/public/**</td>
					<td>(anonymous)</td>
					<td>✓</td><td>✓</td><td>✓</td><td>✓</td>
				</tr>
				<tr>
					<td>/view/**</td>
					<td>viewer</td>
					<td>✓</td><td>✓</td><td>✓</td><td>✗</td>
				</tr>
				<tr>
					<td>/edit/**</td>
					<td>editor</td>
					<td>✓</td><td>✓</td><td>✗</td><td>✗</td>
				</tr>
				<tr>
					<td>/admin/**</td>
					<td>admin</td>
					<td>✓</td><td>✗</td><td>✗</td><td>✗</td>
				</tr>
				<tr>
					<td>/api/write/**</td>
					<td>editor OR admin</td>
					<td>✓</td><td>✓</td><td>✗</td><td>✗</td>
				</tr>
			</table>

			<h2>Try It</h2>
			<ul>
				<li><a href="/public/info">Public Info</a> - Anyone</li>
				<li><a href="/view/dashboard">View Dashboard</a> - Requires viewer</li>
				<li><a href="/edit/content">Edit Content</a> - Requires editor</li>
				<li><a href="/admin/users">Manage Users</a> - Requires admin</li>
			</ul>

			<h2>cURL Examples</h2>
			<pre>
# Public endpoint (no auth)
curl http://localhost:8080/public/info

# View with viewer credentials
curl -u viewer:viewer123 http://localhost:8080/view/dashboard

# Edit with editor credentials
curl -u editor:editor123 http://localhost:8080/edit/content

# Admin with admin credentials
curl -u admin:admin123 http://localhost:8080/admin/users

# Try edit with viewer (will fail - 403 Forbidden)
curl -u viewer:viewer123 http://localhost:8080/edit/content
			</pre>
		`)
		return nil
	})

	// Public endpoint
	engine.Handle("/public/info", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Public Information</h1>
			<p>This page is accessible without authentication.</p>
			<p><a href="/">Back to home</a></p>
		`)
		return nil
	})

	// Viewer endpoint
	engine.Handle("/view/dashboard", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>View Dashboard</h1>
			<p>Welcome, <strong>%s</strong>!</p>
			<p>Your scopes: <code>%v</code></p>
			<p>This page requires 'viewer' scope.</p>
			<p><a href="/">Back to home</a></p>
		`, user.Username, user.Scopes)
		return nil
	})

	// Editor endpoint
	engine.Handle("/edit/content", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>Edit Content</h1>
			<p>Welcome, <strong>%s</strong>!</p>
			<p>Your scopes: <code>%v</code></p>
			<p>This page requires 'editor' scope for write access.</p>
			<p><a href="/">Back to home</a></p>
		`, user.Username, user.Scopes)
		return nil
	})

	// Admin endpoint
	engine.Handle("/admin/users", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>User Management</h1>
			<p>Welcome, Administrator <strong>%s</strong>!</p>
			<p>Your scopes: <code>%v</code></p>
			<p>This page requires 'admin' scope.</p>
			<p><a href="/">Back to home</a></p>
		`, user.Username, user.Scopes)
		return nil
	})

	// API endpoints
	engine.Handle("/api/public/status", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status": "ok", "access": "public"}`)
		return nil
	})

	engine.Handle("/api/read/data", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user": "%s", "scopes": %q, "data": ["item1", "item2"]}`,
			user.Username, user.Scopes)
		return nil
	})

	engine.Handle("/api/write/data", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user": "%s", "scopes": %q, "result": "Data written"}`,
			user.Username, user.Scopes)
		return nil
	})

	engine.Handle("/api/delete/data", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user": "%s", "scopes": %q, "result": "Data deleted"}`,
			user.Username, user.Scopes)
		return nil
	})

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("Test credentials:")
	fmt.Println("  admin:admin123 (admin, editor, viewer)")
	fmt.Println("  editor:editor123 (editor, viewer)")
	fmt.Println("  viewer:viewer123 (viewer)")
	fmt.Println("  guest:guest123 (no scopes)")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
