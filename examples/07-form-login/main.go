// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/security"
)

func main() {
	engine := we.New()

	// Enable session management (required for form-based login)
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).
		CookieName("session_id").
		CookieSecure(false). // Set to true in production with HTTPS
		CookieHttpOnly(true).
		Build()
	engine.SetSessionManager(sessionManager)

	// Define users
	users := []security.User{
		{Username: "admin", Password: "admin123", Scopes: []string{"admin"}},
		{Username: "user", Password: "user123", Scopes: []string{"user"}},
	}

	// Create custom login form
	loginForm := security.DefaultLoginForm(security.LoginFormConfiguration{
		Action: "/login",
		Title:  "Please Login",
	})

	// Create form-based authentication provider
	authProvider := security.LoginFormAuthenticationProvider(users...).
		LoginForm(loginForm).
		Required(true).                                        // Authentication required
		RedirectToForm(true).                                  // Redirect to login form if not authenticated
		DefaultAuthenticatedRedirectionPath("/app/dashboard"). // After login, redirect here
		Build()

	// Configure security filter
	securityFilter := security.Filter(false).
		// Public paths
		Path("/", "/public/**").
		Anonymous().
		// Protected app paths
		Path("/app/**").
		Authentication(authProvider).
		Authorize(). // Requires authentication
		// Admin paths
		Path("/admin/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		Build()

	engine.AddFilter(securityFilter)

	// Public home page
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Form-Based Login Example</h1>
			
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
					<td>admin</td>
				</tr>
				<tr>
					<td>user</td>
					<td>user123</td>
					<td>user</td>
				</tr>
			</table>

			<h2>Try It</h2>
			<ul>
				<li><a href="/app/dashboard">Go to Dashboard</a> - Will redirect to login if not authenticated</li>
				<li><a href="/admin/panel">Go to Admin Panel</a> - Requires admin scope</li>
				<li><a href="/public/info">Public Info</a> - No authentication required</li>
			</ul>
		`)
		return nil
	})

	// Public info page
	engine.Handle("/public/info", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Public Information</h1>
			<p>This page is accessible without authentication.</p>
			<p><a href="/">Back to home</a></p>
		`)
		return nil
	})

	// Protected dashboard
	engine.Handle("/app/dashboard", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>Dashboard</h1>
			<p>Welcome, <strong>%s</strong>!</p>
			<p>Your scopes: <code>%v</code></p>
			<ul>
				<li><a href="/app/profile">My Profile</a></li>
				<li><a href="/admin/panel">Admin Panel</a> (requires admin scope)</li>
				<li><a href="/logout">Logout</a></li>
			</ul>
			<p><a href="/">Back to home</a></p>
		`, user.Username, user.Scopes)
		return nil
	})

	// Profile page
	engine.Handle("/app/profile", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>My Profile</h1>
			<p>Username: <strong>%s</strong></p>
			<p>Scopes: <code>%v</code></p>
			<p><a href="/app/dashboard">Back to Dashboard</a></p>
		`, user.Username, user.Scopes)
		return nil
	})

	// Admin panel
	engine.Handle("/admin/panel", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<h1>Admin Panel</h1>
			<p>Welcome, Administrator <strong>%s</strong>!</p>
			<p>This page is only accessible to users with the 'admin' scope.</p>
			<p><a href="/app/dashboard">Back to Dashboard</a></p>
		`, user.Username)
		return nil
	})

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("Test credentials:")
	fmt.Println("  admin:admin123 (admin scope)")
	fmt.Println("  user:user123 (user scope)")
	fmt.Println()
	fmt.Println("Session timeout: 30 minutes")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
