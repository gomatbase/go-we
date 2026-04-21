// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/security"
)

// Simple token introspector for demonstration
// In production, validate JWT tokens or call an authorization server
type SimpleTokenIntrospector struct {
	validTokens map[string]*security.User
}

func (s *SimpleTokenIntrospector) Introspect(ctx context.Context, token string) (*security.User, error) {
	user, found := s.validTokens[token]
	if !found {
		return nil, fmt.Errorf("invalid token")
	}
	return user, nil
}

func home(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<h1>Bearer Token Authentication Example</h1>
			
			<h2>Test Tokens</h2>
			<table border="1" cellpadding="10">
				<tr>
					<th>Token</th>
					<th>User</th>
					<th>Scopes</th>
				</tr>
				<tr>
					<td>admin-token-123</td>
					<td>admin</td>
					<td>admin, api:read, api:write</td>
				</tr>
				<tr>
					<td>user-token-456</td>
					<td>user</td>
					<td>api:read</td>
				</tr>
				<tr>
					<td>app-token-789</td>
					<td>app-service</td>
					<td>api:read, api:write</td>
				</tr>
			</table>

			<h2>Available Endpoints</h2>
			<ul>
				<li>/api/public/info - Public (no auth)</li>
				<li>/api/read/data - Requires api:read scope</li>
				<li>/api/write/data - Requires api:write scope</li>
				<li>/api/admin/users - Requires admin scope</li>
			</ul>

			<h2>Try with curl</h2>
			<pre>
# Public endpoint (no token needed)
curl http://localhost:8080/api/public/info

# Read endpoint with read token
curl -H "Authorization: Bearer user-token-456" \
     http://localhost:8080/api/read/data

# Write endpoint with write token
curl -H "Authorization: Bearer app-token-789" \
     http://localhost:8080/api/write/data

# Admin endpoint with admin token
curl -H "Authorization: Bearer admin-token-123" \
     http://localhost:8080/api/admin/users

# Try write endpoint with read-only token (will fail)
curl -H "Authorization: Bearer user-token-456" \
     http://localhost:8080/api/write/data
			</pre>
		`)
	return nil
}

func info(w http.ResponseWriter, scope we.RequestScope) error {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"message": "Public API - no authentication required"}`)
	return nil
}

func read(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"message": "Read access granted",
	"user": "%s",
	"scopes": %q,
	"data": ["item1", "item2", "item3"]
}`, user.Username, user.Scopes)
	return nil
}

func write(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"message": "Write access granted",
	"user": "%s",
	"scopes": %q,
	"result": "Data written successfully"
}`, user.Username, user.Scopes)
	return nil
}

func admin(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"message": "Admin access granted",
	"user": "%s",
	"scopes": %q,
	"users": [
		{"id": 1, "name": "admin"},
		{"id": 2, "name": "user"},
		{"id": 3, "name": "app-service"}
	]
}`, user.Username, user.Scopes)
	return nil
}

func main() {

	// Create token introspector with sample tokens
	introspector := &SimpleTokenIntrospector{
		validTokens: map[string]*security.User{
			"admin-token-123": {
				Username: "admin",
				Scopes:   []string{"admin", "api:read", "api:write"},
			},
			"user-token-456": {
				Username: "user",
				Scopes:   []string{"api:read"},
			},
			"app-token-789": {
				Username: "app-service",
				Scopes:   []string{"api:read", "api:write"},
			},
		},
	}

	// Create Bearer authentication provider
	authProvider := security.BearerAuthenticationProvider().
		Introspector(introspector).
		Build()

	// Configure security filter
	securityFilter := security.Filter(false).
		Authentication(authProvider).
		Path("/api/read/**").Authorize(security.Scope("api:read")).   // Protected API - read operations
		Path("/api/write/**").Authorize(security.Scope("api:write")). // Protected API - write operations
		Path("/api/admin/**").Authorize(security.Scope("admin")).     // Admin endpoints
		Build()

	engine := we.New().
		Filter(securityFilter).
		Handle("/", home).                 // Public home page
		Handle("/api/public/info", info).  // Public API endpoint
		Handle("/api/read/data", read).    // Read endpoint
		Handle("/api/write/data", write).  // Write endpoint
		Handle("/api/admin/users", admin). // Admin endpoint
		Build()

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println()
	fmt.Println("Test tokens:")
	fmt.Println("  admin-token-123 (admin, api:read, api:write)")
	fmt.Println("  user-token-456 (api:read)")
	fmt.Println("  app-token-789 (api:read, api:write)")
	fmt.Println()
	fmt.Println("Send tokens in Authorization header: Bearer <token>")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
