// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/filters"
	"github.com/gomatbase/go-we/security"
)

// Data models
type Task struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Completed   bool      `json:"completed"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// In-memory data store
var tasks = make(map[int]Task)
var nextTaskID = 1

// Users with different roles
var users = []security.User{
	{Username: "admin", Password: "admin123", Scopes: []string{"admin", "user"}},
	{Username: "user", Password: "user123", Scopes: []string{"user"}},
}

func main() {
	engine := we.New()

	// 1. Session Management
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).
		CookieName("taskapp_session").
		CookieSecure(false).
		CookieHttpOnly(true).
		CookieSameSite(http.SameSiteLaxMode).
		Build()
	engine.SetSessionManager(sessionManager)

	// 2. CORS Filter
	corsFilter := filters.Cors().
		AllowedOrigins("http://localhost:3000").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowedHeaders("Content-Type", "Authorization").
		AllowCredentials().
		MaxAge(3600).
		Build()
	engine.AddFilter(corsFilter)

	// 3. Security Headers Filter
	securityHeadersFilter := filters.ResponseHeaders().
		HSTS(31536000, true, false).
		FrameOptions(filters.FrameOptionDeny).
		NoSniff().
		ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin).
		Build()
	engine.AddFilter(securityHeadersFilter)

	// 4. Authentication & Authorization
	loginForm := security.DefaultLoginForm(security.LoginFormConfiguration{
		Action: "/login",
		Title:  "Task Manager - Login",
	})

	authProvider := security.LoginFormAuthenticationProvider(users...).
		LoginForm(loginForm).
		Required(true).
		RedirectToForm(true).
		DefaultAuthenticatedRedirectionPath("/app").
		Build()

	securityFilter := security.Filter(false).
		// Public paths
		Path("/", "/public/**", "/api/health").
		Anonymous().
		// App pages - requires authentication
		Path("/app/**").
		Authentication(authProvider).
		Authorize().
		// API - requires user scope
		Path("/api/tasks/**").
		Authentication(authProvider).
		Authorize(security.Scope("user")).
		// Admin API - requires admin scope
		Path("/api/admin/**").
		Authentication(authProvider).
		Authorize(security.Scope("admin")).
		Build()

	engine.AddFilter(securityFilter)

	// Public home page
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<!DOCTYPE html>
			<html>
			<head>
				<title>Task Manager</title>
				<style>
					body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
					.feature { margin: 20px 0; padding: 15px; background: #f5f5f5; }
				</style>
			</head>
			<body>
				<h1>Task Manager Application</h1>
				<p>A complete example demonstrating all go-we features.</p>
				
				<div class="feature">
					<h3>Features</h3>
					<ul>
						<li>Session-based authentication</li>
						<li>Role-based authorization (admin, user)</li>
						<li>RESTful API with JSON</li>
						<li>CORS support</li>
						<li>Security headers</li>
						<li>Error handling</li>
						<li>Form-based login</li>
					</ul>
				</div>

				<h3>Test Credentials</h3>
				<ul>
					<li><strong>admin</strong> / admin123 (admin + user scopes)</li>
					<li><strong>user</strong> / user123 (user scope only)</li>
				</ul>

				<p><a href="/app">Go to Application</a></p>
				<p><a href="/api/health">API Health Check</a></p>
			</body>
			</html>
		`)
		return nil
	})

	// Health check endpoint
	engine.Handle("/api/health", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
		return nil
	})

	// App dashboard
	engine.Handle("/app", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		w.Header().Set("Content-Type", "text/html")
		html := fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<title>Task Manager - Dashboard</title>
				<style>
					body { font-family: Arial; max-width: 1000px; margin: 20px auto; padding: 20px; }
					.task { padding: 15px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
					.task.completed { background: #e8f5e9; }
					input, textarea { width: 100%%; padding: 8px; margin: 5px 0; }
					button { padding: 10px 20px; margin: 5px; cursor: pointer; }
				</style>
			</head>
			<body>
				<h1>Task Manager</h1>
				<p>Welcome, <strong>%s</strong>! | <a href="/logout">Logout</a></p>
				<p>Your scopes: %v</p>

				<h2>Create Task</h2>
				<div id="create-form">
					<input type="text" id="title" placeholder="Task title" />
					<textarea id="description" placeholder="Task description"></textarea>
					<button onclick="createTask()">Create Task</button>
				</div>

				<h2>Your Tasks</h2>
				<div id="tasks"></div>

				<script>
					function loadTasks() {
						fetch('/api/tasks')
							.then(r => r.json())
							.then(tasks => {
								const container = document.getElementById('tasks');
								if (!tasks || tasks.length === 0) {
									container.innerHTML = '<p>No tasks yet. Create one!</p>';
									return;
								}
								container.innerHTML = tasks.map(task => `+"`"+`
									<div class="task ${task.completed ? 'completed' : ''}">
										<h3>${task.title}</h3>
										<p>${task.description}</p>
										<small>Created by: ${task.created_by} at ${new Date(task.created_at).toLocaleString()}</small>
										<br/>
										<button onclick="toggleTask(${task.id}, ${task.completed})">${task.completed ? 'Mark Incomplete' : 'Mark Complete'}</button>
										<button onclick="deleteTask(${task.id})">Delete</button>
									</div>
								`+"`"+`).join('');
							});
					}

					function createTask() {
						const title = document.getElementById('title').value;
						const description = document.getElementById('description').value;
						
						fetch('/api/tasks', {
							method: 'POST',
							headers: {'Content-Type': 'application/json'},
							body: JSON.stringify({title, description})
						}).then(() => {
							document.getElementById('title').value = '';
							document.getElementById('description').value = '';
							loadTasks();
						});
					}

					function toggleTask(id, completed) {
						fetch('/api/tasks/' + id, {
							method: 'PUT',
							headers: {'Content-Type': 'application/json'},
							body: JSON.stringify({completed: !completed})
						}).then(loadTasks);
					}

					function deleteTask(id) {
						if (confirm('Delete this task?')) {
							fetch('/api/tasks/' + id, {method: 'DELETE'})
								.then(loadTasks);
						}
					}

					// Load tasks on page load
					loadTasks();
				</script>
			</body>
			</html>
		`, user.Username, user.Scopes)

		fmt.Fprint(w, html)
		return nil
	})

	// API: List tasks
	engine.HandleMethod("GET", "/api/tasks", func(w http.ResponseWriter, scope we.RequestScope) error {
		taskList := make([]Task, 0, len(tasks))
		for _, task := range tasks {
			taskList = append(taskList, task)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(taskList)
		return nil
	})

	// API: Create task
	engine.HandleMethod("POST", "/api/tasks", func(w http.ResponseWriter, scope we.RequestScope) error {
		user := scope.Get("user").(*security.User)

		body, _ := io.ReadAll(scope.Request().Body)

		var task Task
		if err := json.Unmarshal(body, &task); err != nil {
			return events.New(400, "Invalid JSON")
		}

		if task.Title == "" {
			return events.New(400, "Title is required")
		}

		task.ID = nextTaskID
		nextTaskID++
		task.CreatedBy = user.Username
		task.CreatedAt = time.Now()
		task.Completed = false

		tasks[task.ID] = task

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(task)
		return nil
	})

	// API: Update task
	engine.HandleMethod("PUT", "/api/tasks/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
		var taskID int
		fmt.Sscanf(scope.Var("id"), "%d", &taskID)

		task, found := tasks[taskID]
		if !found {
			return events.New(404, "Task not found")
		}

		body, _ := io.ReadAll(scope.Request().Body)
		var updates map[string]interface{}
		json.Unmarshal(body, &updates)

		if title, ok := updates["title"].(string); ok {
			task.Title = title
		}
		if desc, ok := updates["description"].(string); ok {
			task.Description = desc
		}
		if completed, ok := updates["completed"].(bool); ok {
			task.Completed = completed
		}

		tasks[taskID] = task

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(task)
		return nil
	})

	// API: Delete task
	engine.HandleMethod("DELETE", "/api/tasks/{id}", func(w http.ResponseWriter, scope we.RequestScope) error {
		var taskID int
		fmt.Sscanf(scope.Var("id"), "%d", &taskID)

		if _, found := tasks[taskID]; !found {
			return events.New(404, "Task not found")
		}

		delete(tasks, taskID)
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	// Admin: List all users (admin only)
	engine.Handle("/api/admin/users", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
		return nil
	})

	log.Println("Task Manager Application")
	log.Println("=========================")
	log.Println("Server starting on http://localhost:8080")
	log.Println()
	log.Println("Features enabled:")
	log.Println("  ✓ Session management")
	log.Println("  ✓ Form-based authentication")
	log.Println("  ✓ Role-based authorization")
	log.Println("  ✓ CORS support")
	log.Println("  ✓ Security headers")
	log.Println("  ✓ RESTful API")
	log.Println()
	log.Println("Test credentials:")
	log.Println("  admin:admin123 (admin + user scopes)")
	log.Println("  user:user123 (user scope)")
	log.Println()
	log.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		log.Fatalf("Server error: %v\n", err)
	}
}
