// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
)

func main() {
	engine := we.New()

	// Configure session manager using the builder pattern
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).        // Sessions expire after 30 minutes of inactivity
		CookieName("go_we_session").             // Custom cookie name
		CookieSecure(false).                     // Set to true in production with HTTPS
		CookieSameSite(http.SameSiteLaxMode).    // CSRF protection
		CookieHttpOnly(true).                    // Prevent XSS attacks
		SessionPurgingInterval(5 * time.Minute). // Clean up expired sessions every 5 minutes
		Build()

	engine.SetSessionManager(sessionManager)

	// Home page
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		visitCount := 0

		// Get visit count from session (if exists)
		if count := scope.GetFromSession("visit_count"); count != nil {
			visitCount = count.(int)
		}

		// Increment and save
		visitCount++
		scope.SetInSession("visit_count", visitCount)

		// Check if user is logged in
		username := scope.GetFromSession("username")
		isLoggedIn := username != nil

		w.Header().Set("Content-Type", "text/html")

		html := fmt.Sprintf(`
			<h1>Session Management Example</h1>
			<p>You have visited this page <strong>%d</strong> time(s) in this session.</p>
		`, visitCount)

		if isLoggedIn {
			html += fmt.Sprintf(`
				<p>Welcome back, <strong>%s</strong>!</p>
				<ul>
					<li><a href="/profile">View Profile</a></li>
					<li><a href="/logout">Logout</a></li>
				</ul>
			`, username.(string))
		} else {
			html += `
				<p>You are not logged in.</p>
				<ul>
					<li><a href="/login">Login</a></li>
				</ul>
			`
		}

		html += `
			<h2>Available Examples</h2>
			<ul>
				<li><a href="/set-preference">Set Preference</a></li>
				<li><a href="/view-preference">View Preference</a></li>
				<li><a href="/clear-session">Clear Session Data</a></li>
			</ul>
		`

		fmt.Fprint(w, html)
		return nil
	})

	// Login page
	engine.HandleMethod("GET", "/login", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Login</h1>
			<form method="POST">
				<input type="text" name="username" placeholder="Username" required>
				<button type="submit">Login</button>
			</form>
			<p><a href="/">Back to home</a></p>
		`)
		return nil
	})

	// Login handler
	engine.HandleMethod("POST", "/login", func(w http.ResponseWriter, scope we.RequestScope) error {
		scope.Request().ParseForm()
		username := scope.Request().FormValue("username")

		// Store username in session
		scope.SetInSession("username", username)
		scope.SetInSession("login_time", time.Now().Format(time.RFC1123))

		http.Redirect(w, scope.Request(), "/", http.StatusSeeOther)
		return nil
	})

	// Profile page (requires login)
	engine.Handle("/profile", func(w http.ResponseWriter, scope we.RequestScope) error {
		username := scope.GetFromSession("username")
		if username == nil {
			http.Redirect(w, scope.Request(), "/login", http.StatusSeeOther)
			return nil
		}

		loginTime := scope.GetFromSession("login_time")
		visitCount := scope.GetFromSession("visit_count")

		w.Header().Set("Content-Type", "text/html")
		html := fmt.Sprintf(`
			<h1>User Profile</h1>
			<p>Username: <strong>%s</strong></p>
			<p>Login time: <strong>%s</strong></p>
			<p>Page visits this session: <strong>%d</strong></p>
			<p><a href="/">Back to home</a></p>
		`, username.(string), loginTime.(string), visitCount.(int))

		fmt.Fprint(w, html)
		return nil
	})

	// Logout
	engine.Handle("/logout", func(w http.ResponseWriter, scope we.RequestScope) error {
		// Remove user-related session data
		scope.SetInSession("username", nil)
		scope.SetInSession("login_time", nil)

		http.Redirect(w, scope.Request(), "/", http.StatusSeeOther)
		return nil
	})

	// Set a preference in session
	engine.HandleMethod("GET", "/set-preference", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Set Theme Preference</h1>
			<form method="POST">
				<label>
					<input type="radio" name="theme" value="light" required> Light
				</label>
				<label>
					<input type="radio" name="theme" value="dark"> Dark
				</label>
				<button type="submit">Save Preference</button>
			</form>
			<p><a href="/">Back to home</a></p>
		`)
		return nil
	})

	engine.HandleMethod("POST", "/set-preference", func(w http.ResponseWriter, scope we.RequestScope) error {
		scope.Request().ParseForm()
		theme := scope.Request().FormValue("theme")

		scope.SetInSession("theme", theme)

		http.Redirect(w, scope.Request(), "/view-preference", http.StatusSeeOther)
		return nil
	})

	// View preference from session
	engine.Handle("/view-preference", func(w http.ResponseWriter, scope we.RequestScope) error {
		theme := scope.GetFromSession("theme")

		w.Header().Set("Content-Type", "text/html")

		var themeText string
		if theme == nil {
			themeText = "No theme preference set"
		} else {
			themeText = fmt.Sprintf("Your theme preference: <strong>%s</strong>", theme.(string))
		}

		html := fmt.Sprintf(`
			<h1>Theme Preference</h1>
			<p>%s</p>
			<p><a href="/set-preference">Change preference</a></p>
			<p><a href="/">Back to home</a></p>
		`, themeText)

		fmt.Fprint(w, html)
		return nil
	})

	// Clear all session data (except the session itself)
	engine.Handle("/clear-session", func(w http.ResponseWriter, scope we.RequestScope) error {
		// Note: Setting values to nil removes them from the session
		scope.SetInSession("username", nil)
		scope.SetInSession("login_time", nil)
		scope.SetInSession("theme", nil)
		// visit_count is kept to show that sessions persist even after clearing data

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Session Cleared</h1>
			<p>All session data (except visit count) has been cleared.</p>
			<p><a href="/">Back to home</a></p>
		`)
		return nil
	})

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Session timeout: 30 minutes")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
