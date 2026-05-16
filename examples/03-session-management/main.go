// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
)

// home handler to prsent the home page of the session manager example. It displays the visit count for the current
// session and provides links to login, view profile, set preferences, and clear session data.
func home(w http.ResponseWriter, scope we.RequestScope) error {
	visitCount := 0

	// Get visit count from session (if exists)
	if count := scope.Session().Get("visit_count"); count != nil {
		visitCount = count.(int)
	}

	// Increment and save
	visitCount++
	scope.Session().Set("visit_count", visitCount)

	// Check if user is logged in
	username := scope.Session().Get("username")
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
}

// loginPage handler serves the login form where users can enter their username to log in. It displays a simple HTML form.
func loginPage(w http.ResponseWriter, scope we.RequestScope) error {
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
}

// login handler processes the login form submission. It retrieves the username from the form, stores it in the
// session along with the login time, and redirects the user back to the home page.
func login(w http.ResponseWriter, scope we.RequestScope) error {
	scope.Request().ParseForm()
	username := scope.Request().FormValue("username")

	// Store username in session
	scope.Session().Set("username", username)
	scope.Session().Set("login_time", time.Now().Format(time.RFC1123))

	http.Redirect(w, scope.Request(), "/", http.StatusSeeOther)
	return nil
}

// profile handler displays the user's profile information. It checks if the user is logged in by looking for the
// username in the session.
func profile(w http.ResponseWriter, scope we.RequestScope) error {
	username := scope.Session().Get("username")
	if username == nil {
		http.Redirect(w, scope.Request(), "/login", http.StatusSeeOther)
		return nil
	}

	loginTime := scope.Session().Get("login_time")
	visitCount := scope.Session().Get("visit_count")

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
}

// logout handler logs the user out by clearing the username and login time from the session. It then redirects the
// user back to the home page.
func logout(w http.ResponseWriter, scope we.RequestScope) error {
	// Remove user-related session data
	scope.Session().Delete("username")
	scope.Session().Delete("login_time")

	http.Redirect(w, scope.Request(), "/", http.StatusSeeOther)
	return nil
}

// setPreferenceForm handler serves a form that allows users to set a theme preference (light or dark). The selected
// preference is stored in the session when the form is submitted. This demonstrates how to use sessions to store user
// preferences.
func setPreferenceForm(w http.ResponseWriter, scope we.RequestScope) error {
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
}

// setPreference handler processes the theme preference form submission. It retrieves the selected theme from the form,
// stores it in the session, and redirects the user to the view preference page to see their saved preference.
func setPreference(w http.ResponseWriter, scope we.RequestScope) error {
	scope.Request().ParseForm()
	theme := scope.Request().FormValue("theme")

	scope.Session().Set("theme", theme)

	http.Redirect(w, scope.Request(), "/view-preference", http.StatusSeeOther)
	return nil
}

// viewPreference handler displays the user's saved theme preference. It retrieves the theme from the session and shows it
// on the page. If no preference is set, it informs the user that no theme preference is set.
func viewPreference(w http.ResponseWriter, scope we.RequestScope) error {
	theme := scope.Session().Get("theme")

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
}

// clearSession handler demonstrates how to clear session data without destroying the session itself. It removes specific keys
// from the session, allowing the session to persist while clearing user-specific data. This is useful for scenarios like
// logging out or resetting preferences without losing the session context (like visit count).
func clearSession(w http.ResponseWriter, scope we.RequestScope) error {
	// Remove specific session attributes
	scope.Session().Delete("username")
	scope.Session().Delete("login_time")
	scope.Session().Delete("theme")
	// visit_count is kept to show that sessions persist even after clearing data

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<h1>Session Cleared</h1>
			<p>All session data (except visit count) has been cleared.</p>
			<p><a href="/">Back to home</a></p>
		`)
	return nil
}

func main() {
	// Configure session manager using the builder pattern
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).        // Sessions expire after 30 minutes of inactivity
		CookieName("go_we_session").             // Custom cookie name
		CookieSecure(false).                     // Set to true in production with HTTPS
		CookieSameSite(http.SameSiteLaxMode).    // CSRF protection
		CookieHttpOnly(true).                    // Prevent XSS attacks
		SessionPurgingInterval(5 * time.Minute). // Clean up expired sessions every 5 minutes
		Build()

	engine := we.New().
		SessionManager(sessionManager).
		Handle("/", home).                                         // Home page
		HandleMethod("GET", "/login", loginPage).                  // Login page
		HandleMethod("POST", "/login", login).                     // Login handler
		Handle("/profile", profile).                               // Profile page (requires login)
		Handle("/logout", logout).                                 // Logout
		HandleMethod("GET", "/set-preference", setPreferenceForm). // Set a preference in session
		HandleMethod("POST", "/set-preference", setPreference).    // Save preference to session
		Handle("/view-preference", viewPreference).                // View preference from session
		Handle("/clear-session", clearSession).                    // Clear all session data (except the session itself)
		Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Session timeout: 30 minutes")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
