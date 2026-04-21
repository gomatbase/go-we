// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/security"
)

func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<h1>Basic Authentication Example</h1>
			
			<h2>Test Credentials</h2>
			<table border="1" cellpadding="10">
				<tr>
					<th>Username</th>
					<th>Password</th>
					<th>Scopes</th>
				</tr>
				<tr>
					<td>admin</td>
					<td>admin123</td>
					<td>admin, user</td>
				</tr>
				<tr>
					<td>user</td>
					<td>user123</td>
					<td>user</td>
				</tr>
				<tr>
					<td>guest</td>
					<td>guest123</td>
					<td>(none)</td>
				</tr>
			</table>

			<h2>Available Endpoints</h2>
			<ul>
				<li><a href="/">/</a> - Public (no auth required)</li>
				<li><a href="/user/dashboard">/user/dashboard</a> - Requires user or admin</li>
				<li><a href="/admin/panel">/admin/panel</a> - Requires admin only</li>
				<li><a href="/api/data">/api/data</a> - Requires authentication (any user)</li>
			</ul>

			<h2>Try with curl</h2>
			<pre>
# Without credentials (will fail)
curl http://localhost:8080/admin/panel

# With admin credentials (will succeed)
curl -u admin:admin123 http://localhost:8080/admin/panel

# With user credentials (will fail - no admin scope)
curl -u user:user123 http://localhost:8080/admin/panel

# With user credentials on user endpoint (will succeed)
curl -u user:user123 http://localhost:8080/user/dashboard

# API endpoint with any valid user
curl -u guest:guest123 http://localhost:8080/api/data
			</pre>
		`)
	return nil
}

func dashboard(w http.ResponseWriter, scope we.RequestScope) error {
	// Get authenticated user from scope
	user := security.GetUser(scope)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h1>User Dashboard</h1>
			<p>Welcome, <strong>%s</strong>!</p>
			<p>Your scopes: <code>%v</code></p>
			<p><a href="/">Back to home</a></p>
		`, user.Username, user.Scopes)
	return nil
}

func panel(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
			<h1>Admin Panel</h1>
			<p>Welcome, Administrator <strong>%s</strong>!</p>
			<p>Your scopes: <code>%v</code></p>
			<p>This page is only accessible to users with the 'admin' scope.</p>
			<p><a href="/">Back to home</a></p>
		`, user.Username, user.Scopes)
	return nil
}

func data(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"message": "API access granted",
	"user": "%s",
	"scopes": %q
}`, user.Username, user.Scopes)
	return nil
}

func main() {

	// Configure Basic Authentication
	// Create users with credentials
	users := []security.User{
		{Username: "admin", Password: "admin123", Scopes: []string{"admin", "user"}},
		{Username: "user", Password: "user123", Scopes: []string{"user"}},
		{Username: "guest", Password: "guest123", Scopes: []string{}},
	}

	// Create security filter with Basic Authentication
	authProvider := security.BasicAuthenticationProvider(users...).Build()

	securityFilter := security.Filter(false). // Allow anonymous access by default
		// Protect admin paths - requires admin scope
		Path("/admin/**").Authentication(authProvider).Authorize(security.Scope("admin")).
		// Protect user paths - requires user scope
		Path("/user/**").Authentication(authProvider).Authorize(security.Scope("user")).
		// Protect API paths - requires authentication (any user)
		Path("/api/**").Authentication(authProvider).Authorize().
		Build()

	engine := we.New().
		Filter(securityFilter).
		Handle("/", home).                    // Public home page
		Handle("/user/dashboard", dashboard). // User dashboard - requires "user" scope
		Handle("/admin/panel", panel).        // Admin panel - requires "admin" scope
		Handle("/api/data", data).            // API endpoint - requires authentication but no specific scope
		Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("Test credentials:")
	fmt.Println("  admin:admin123 (admin, user scopes)")
	fmt.Println("  user:user123 (user scope)")
	fmt.Println("  guest:guest123 (no scopes)")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
