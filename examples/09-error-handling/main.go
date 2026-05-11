// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

// TODO: change this to an actual error handling example.

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<h1>Error Handling Example</h1>
			
			<h2>Try These Error Scenarios</h2>
			<ul>
				<li><a href="/error/400">400 Bad Request</a></li>
				<li><a href="/error/401">401 Unauthorized</a></li>
				<li><a href="/error/403">403 Forbidden</a></li>
				<li><a href="/error/404">404 Not Found</a></li>
				<li><a href="/error/500">500 Internal Server Error</a></li>
				<li><a href="/error/custom">Custom Error with Message</a></li>
				<li><a href="/error/payload">Custom Error with JSON Payload</a></li>
				<li><a href="/error/panic">Handled Panic</a></li>
			</ul>

			<h2>Built-in Error Events</h2>
			<pre>
events.BadRequestError        // 400
events.UnauthorizedError      // 401
events.ForbiddenError         // 403
events.NotFoundError          // 404
events.InternalServerError    // 500
			</pre>

			<h2>Custom Errors</h2>
			<pre>
// Simple error with status code and message
return events.New(418, "I'm a teapot")

// Error with custom JSON payload
jsonPayload := `+"`"+`{"error": "validation failed"}`+"`"+`
return events.NewPayload(422, "Validation failed", &events.Payload{
    ContentTypeHint: "application/json",
    Content:         []byte(jsonPayload),
})
			</pre>

			<h2>cURL Examples</h2>
			<pre>
curl http://localhost:8080/error/404 -v
curl http://localhost:8080/error/401 -v
curl http://localhost:8080/error/custom -v
			</pre>
		`)
	return nil
}

func badRequest(w http.ResponseWriter, scope we.RequestScope) error {
	return events.BadRequestError
}

func unauthorized(w http.ResponseWriter, scope we.RequestScope) error {
	return events.UnauthorizedError
}

func forbidden(w http.ResponseWriter, scope we.RequestScope) error {
	return events.ForbiddenError
}

func notFound(w http.ResponseWriter, scope we.RequestScope) error {
	return events.NotFoundError
}

func internalError(w http.ResponseWriter, scope we.RequestScope) error {
	return events.InternalServerError
}

func customError(w http.ResponseWriter, scope we.RequestScope) error {
	return events.New(422, "Validation failed: email is required")
}

func payload(w http.ResponseWriter, scope we.RequestScope) error {
	jsonPayload := `{
	"errors": [
		{"field": "email", "message": "required"},
		{"field": "password", "message": "too short"}
	]
}`
	return events.NewPayload(422, "Validation failed", &events.Payload{
		ContentTypeHint: "application/json",
		Content:         []byte(jsonPayload),
	})
}

func panicError(w http.ResponseWriter, scope we.RequestScope) error {
	panic("Something went wrong!")
}

func validate(w http.ResponseWriter, scope we.RequestScope) error {
	email := scope.Parameter("email")

	if email == "" {
		return events.New(400, "Email parameter is required")
	}

	if len(email) < 5 {
		return events.New(400, "Email must be at least 5 characters")
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Email is valid", "email": "%s"}`, email)
	return nil
}

func jsonErrors(w http.ResponseWriter, scope we.RequestScope) error {
	userId := scope.Var("id")

	// Simulate user not found
	if userId == "999" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"error": "User not found", "user_id": "999"}`)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id": "%s", "name": "User %s"}`, userId, userId)
	return nil
}

func main() {
	engine := we.New().
		Handle("/", home).                    // Home page with examples
		Handle("/error/400", badRequest).     // 400 Bad Request
		Handle("/error/401", unauthorized).   // 401 Unauthorized
		Handle("/error/403", forbidden).      // 403 Forbidden
		Handle("/error/404", notFound).       // 404 Not Found
		Handle("/error/500", internalError).  // 500 Internal Server Error
		Handle("/error/custom", customError). // Custom error with message
		Handle("/error/payload", payload).    // Custom error with payload
		Handle("/error/panic", panicError).   // Panic handling (framework catches panics and treats them as errors)
		Handle("/validate", validate).        // Conditional error
		Handle("/api/user/{id}", jsonErrors). // API endpoint returning JSON errors
		Build()

	log.Println("Server starting on http://localhost:8080")
	log.Println("Custom error handler installed")
	log.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}
