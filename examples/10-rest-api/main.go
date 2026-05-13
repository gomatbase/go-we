// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/util"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// In-memory user store
var users = map[int]*User{
	1: {ID: 1, Name: "Alice", Email: "alice@example.com"},
	2: {ID: 2, Name: "Bob", Email: "bob@example.com"},
	3: {ID: 3, Name: "Charlie", Email: "charlie@example.com"},
}
var nextID = 4

func home(w http.ResponseWriter, scope we.RequestScope) error {
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
}

func listUsers(w http.ResponseWriter, _ we.RequestScope) error {
	userList := make([]*User, 0, len(users))
	for _, user := range users {
		userList = append(userList, user)
	}

	return util.ReplyJson(w, http.StatusOK, userList)
}

func getUser(w http.ResponseWriter, scope we.RequestScope) error {
	id := scope.Var("id")

	var userID int
	if _, err := fmt.Sscanf(id, "%d", &userID); err != nil {
		return events.New(400, "Invalid user ID")
	}

	user, found := users[userID]
	if !found {
		return events.New(404, "User not found")
	}

	return util.ReplyJson(w, http.StatusOK, user)
}

func newUser(w http.ResponseWriter, scope we.RequestScope) error {
	// Parse JSON
	user, err := util.ReadJsonBody[User](scope)
	if err != nil {
		return events.New(400, "Invalid JSON")
	}

	// Validate
	if user.Name == "" {
		return events.New(400, "Name is required")
	}
	if user.Email == "" {
		return events.New(400, "Email is required")
	}

	// Assign ID and save
	user.ID = nextID
	nextID++
	users[user.ID] = user

	// Return created user
	return util.ReplyJson(w, http.StatusCreated, user)
}

func updateUser(w http.ResponseWriter, scope we.RequestScope) error {
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
	updatedUser, err := util.ReadJsonBody[User](scope)
	if err != nil {
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

	return util.ReplyJson(w, http.StatusOK, updatedUser)
}

func deleteUser(w http.ResponseWriter, scope we.RequestScope) error {
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
}

func main() {
	engine := we.New().
		Handle("/", home).                                     // Home page with API documentation
		HandleMethod("GET", "/api/users", listUsers).          // GET /api/users - List all users
		HandleMethod("GET", "/api/users/{id}", getUser).       // GET /api/users/{id} - Get user by ID
		HandleMethod("POST", "/api/users", newUser).           // POST /api/users - Create new user
		HandleMethod("PUT", "/api/users/{id}", updateUser).    // PUT /api/users/{id} - Update user
		HandleMethod("DELETE", "/api/users/{id}", deleteUser). // DELETE /api/users/{id} - Delete user
		Build()

	log.Println("Server starting on http://localhost:8080")
	log.Println("REST API with JSON request/response")
	log.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}
