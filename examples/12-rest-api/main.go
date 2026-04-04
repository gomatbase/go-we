// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// In-memory user store
var users = map[int]User{
	1: {ID: 1, Name: "Alice", Email: "alice@example.com"},
	2: {ID: 2, Name: "Bob", Email: "bob@example.com"},
	3: {ID: 3, Name: "Charlie", Email: "charlie@example.com"},
}
var nextID = 4

func main() {
	engine := we.New()

	// Home page with API documentation
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>REST API Example</h1>
			
			<h2>API Endpoints</h2>
			<table border="1" cellpadding="10">
				<tr>
					<th>Method</th>
					<th>Endpoint</th>
					<th>Description</th>
				</tr>
				<tr>
					<td>GET</td>
					<td>/api/users</td>
					<td>List all users</td>
				</tr>
				<tr>
					<td>GET</td>
					<td>/api/users/{id}</td>
					<td>Get user by ID</td>
				</tr>
				<tr>
					<td>POST</td>
					<td>/api/users</td>
					<td>Create new user</td>
				</tr>
				<tr>
					<td>PUT</td>
					<td>/api/users/{id}</td>
					<td>Update user</td>
				</tr>
				<tr>
					<td>DELETE</td>
					<td>/api/users/{id}</td>
					<td>Delete user</td>
				</tr>
			</table>

			<h2>cURL Examples</h2>
			<pre>
# List all users
curl http://localhost:8080/api/users

# Get specific user
curl http://localhost:8080/api/users/1

# Create user
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"David","email":"david@example.com"}'

# Update user
curl -X PUT http://localhost:8080/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice Updated","email":"alice.new@example.com"}'

# Delete user
curl -X DELETE http://localhost:8080/api/users/3
			</pre>
		`)
		return nil
	})

	// GET /api/users - List all users
	engine.HandleMethod("GET", "/api/users", func(w http.ResponseWriter, scope we.RequestScope) error {
		userList := make([]User, 0, len(users))
		for _, user := range users {
			userList = append(userList, user)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userList)
		return nil
	})

	// GET /api/users/{id} - Get user by ID
	engine.HandleMethod("GET", "/api/users/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
		id := scope.Var("id")

		var userID int
		if _, err := fmt.Sscanf(id, "%d", &userID); err != nil {
			return events.New(400, "Invalid user ID")
		}

		user, found := users[userID]
		if !found {
			return events.New(404, "User not found")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
		return nil
	})

	// POST /api/users - Create new user
	engine.HandleMethod("POST", "/api/users", func(w http.ResponseWriter, scope we.RequestScope) error {
		// Read request body
		body, err := io.ReadAll(scope.Request().Body)
		if err != nil {
			return events.New(400, "Failed to read request body")
		}

		// Parse JSON
		var newUser User
		if err := json.Unmarshal(body, &newUser); err != nil {
			return events.New(400, "Invalid JSON")
		}

		// Validate
		if newUser.Name == "" {
			return events.New(400, "Name is required")
		}
		if newUser.Email == "" {
			return events.New(400, "Email is required")
		}

		// Assign ID and save
		newUser.ID = nextID
		nextID++
		users[newUser.ID] = newUser

		// Return created user
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newUser)
		return nil
	})

	// PUT /api/users/{id} - Update user
	engine.HandleMethod("PUT", "/api/users/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
		id := scope.Var("id")

		var userID int
		if _, err := fmt.Sscanf(id, "%d", &userID); err != nil {
			return events.New(400, "Invalid user ID")
		}

		// Check if user exists
		if _, found := users[userID]; !found {
			return events.New(404, "User not found")
		}

		// Read and parse request body
		body, err := io.ReadAll(scope.Request().Body)
		if err != nil {
			return events.New(400, "Failed to read request body")
		}

		var updatedUser User
		if err := json.Unmarshal(body, &updatedUser); err != nil {
			return events.New(400, "Invalid JSON")
		}

		// Validate
		if updatedUser.Name == "" {
			return events.New(400, "Name is required")
		}
		if updatedUser.Email == "" {
			return events.New(400, "Email is required")
		}

		// Update user
		updatedUser.ID = userID
		users[userID] = updatedUser

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updatedUser)
		return nil
	})

	// DELETE /api/users/{id} - Delete user
	engine.HandleMethod("DELETE", "/api/users/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
		id := scope.Var("id")

		var userID int
		if _, err := fmt.Sscanf(id, "%d", &userID); err != nil {
			return events.New(400, "Invalid user ID")
		}

		// Check if user exists
		if _, found := users[userID]; !found {
			return events.New(404, "User not found")
		}

		// Delete user
		delete(users, userID)

		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	log.Println("Server starting on http://localhost:8080")
	log.Println("REST API with JSON request/response")
	log.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}
