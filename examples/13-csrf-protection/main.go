// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/filters"
)

// home handler - renders an HTML form with the CSRF token embedded as a hidden field.
// GET requests automatically generate a CSRF token stored in the session.
func home(w http.ResponseWriter, scope we.RequestScope) error {
	// Retrieve the CSRF token from the session. The CSRF filter automatically
	// generates and stores a token on safe methods (GET, HEAD, OPTIONS).
	token := scope.Session().Get("_csrf_token")

	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>CSRF Protection Example</title></head>
<body>
    <h1>CSRF Protection Example</h1>

    <h2>Protected Form</h2>
    <p>This form includes a CSRF token as a hidden field. The server validates
    the token on POST to prevent cross-site request forgery.</p>
    <form action="/submit" method="POST">
        <input type="hidden" name="_csrf" value="%s">
        <label for="message">Message:</label>
        <input type="text" name="message" id="message" placeholder="Enter a message">
        <button type="submit">Submit</button>
    </form>

    <h2>Exempt Endpoint</h2>
    <p>The <code>/api/webhook</code> endpoint is exempt from CSRF validation,
    useful for machine-to-machine API calls.</p>
    <pre>curl -X POST http://localhost:8080/api/webhook -d '{"event":"test"}'</pre>

    <h2>Test CSRF Rejection</h2>
    <p>A POST to <code>/submit</code> without a valid token will be rejected:</p>
    <pre>curl -X POST http://localhost:8080/submit -d "message=hello"</pre>
</body>
</html>`, token)
	return nil
}

// submitForm handler - processes the form submission. This endpoint is protected
// by the CSRF filter, which validates the token before the handler is reached.
func submitForm(w http.ResponseWriter, scope we.RequestScope) error {
	_ = scope.Request().ParseForm()
	message := scope.Request().FormValue("message")

	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Form Submitted</title></head>
<body>
    <h1>Form Submitted Successfully</h1>
    <p>Your message: <strong>%s</strong></p>
    <p>The CSRF token was validated by the filter before this handler executed.</p>
    <p><a href="/">Go back</a></p>
</body>
</html>`, message)
	return nil
}

// webhook handler - an API endpoint exempt from CSRF validation.
// External services can POST to this endpoint without a CSRF token.
func webhook(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"status":"ok","message":"webhook received"}`)
	return nil
}

func main() {
	// Create a session manager. Sessions are required for CSRF protection
	// because the token is stored in the user's session.
	sessionManager := we.DefaultSessionManager().Build()

	// Create the CSRF filter. Safe methods (GET, HEAD, OPTIONS) automatically
	// generate a token in the session. State-changing methods (POST, PUT, DELETE,
	// PATCH) require the token to be sent via the X-CSRF-Token header or the
	// _csrf form field.
	csrfFilter := filters.Csrf().
		ExemptPaths("/api/webhook"). // Webhook endpoint does not require CSRF validation
		Build()

	// Build the engine with session management, CSRF filter, and route handlers
	engine := we.New().
		SessionManager(sessionManager).
		Filter(csrfFilter).
		HandleMethod("GET", "/", home).                // Renders the form with the CSRF token
		HandleMethod("POST", "/submit", submitForm).   // Protected by CSRF filter
		HandleMethod("POST", "/api/webhook", webhook). // Exempt from CSRF validation
		Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
