// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/filters"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/util"
)

// Data models

type Task struct {
	ID          int       `json:"id"`
	Title       *string   `json:"title"`
	Description *string   `json:"description"`
	Completed   *bool     `json:"completed"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type Health struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

func NewHealth() *Health {
	return &Health{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// In-memory data store
var tasks = make(map[int]*Task)
var nextTaskID = 1
var falsePlaceholder = false

// Users with different roles
var users = []security.User{
	{Username: "admin", Password: "admin123", Scopes: []string{"admin", "user"}},
	{Username: "user", Password: "user123", Scopes: []string{"user"}},
}

func home(w http.ResponseWriter, scope we.RequestScope) error {
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
}

func health(w http.ResponseWriter, _ we.RequestScope) error {
	return util.ReplyJson(w, http.StatusOK, NewHealth())
}

func app(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

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
}

func list(w http.ResponseWriter, _ we.RequestScope) error {
	taskList := make([]*Task, 0, len(tasks))
	for _, task := range tasks {
		taskList = append(taskList, task)
	}

	return util.ReplyJson(w, http.StatusOK, taskList)
}

func create(w http.ResponseWriter, scope we.RequestScope) error {
	user := security.GetUser(scope)

	task, err := util.ReadJsonBody[Task](scope)
	if err != nil {
		return events.New(400, "Invalid JSON")
	}

	if task.Title == nil || *task.Title == "" {
		return events.New(400, "Title is required")
	}

	task.ID = nextTaskID
	nextTaskID++
	task.CreatedBy = user.Username
	task.CreatedAt = time.Now()
	task.Completed = &falsePlaceholder

	tasks[task.ID] = task

	return util.ReplyJson(w, http.StatusCreated, task)
}

func update(w http.ResponseWriter, scope we.RequestScope) error {
	var taskID int
	fmt.Sscanf(scope.Var("id"), "%d", &taskID)

	task, found := tasks[taskID]
	if !found {
		return events.New(404, "Task not found")
	}

	updatedTask, err := util.ReadJsonBody[Task](scope)
	if err != nil {
		return events.New(400, "Invalid JSON")
	}

	if updatedTask.Title != nil {
		if *updatedTask.Title == "" {
			return events.New(400, "Title is required")
		}
		task.Title = updatedTask.Title
	}
	if updatedTask.Description != nil {
		task.Description = updatedTask.Description
	}
	if updatedTask.Completed != nil {
		task.Completed = updatedTask.Completed
	}

	tasks[taskID] = task

	return util.ReplyJson(w, http.StatusOK, task)
}

func del(w http.ResponseWriter, scope we.RequestScope) error {
	var taskID int
	fmt.Sscanf(scope.Var("id"), "%d", &taskID)

	if _, found := tasks[taskID]; !found {
		return events.New(404, "Task not found")
	}

	delete(tasks, taskID)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func admin(w http.ResponseWriter, scope we.RequestScope) error {
	return util.ReplyJson(w, http.StatusOK, users)
}

func logout(w http.ResponseWriter, scope we.RequestScope) error {
	scope.SetInSession(security.UserAttributeName, nil)
	return events.FoundRedirect.WithAttribute("/")
}

func main() {

	// 1. Session Management
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(30 * time.Minute).
		CookieName("taskapp_session").
		CookieSecure(false).
		CookieHttpOnly(true).
		CookieSameSite(http.SameSiteLaxMode).
		Build()

	// 2. CORS Filter
	corsFilter := filters.Cors().
		AllowedOrigins("http://localhost:3000").
		AllowedMethods("GET", "POST", "PUT", "DELETE").
		AllowedHeaders("Content-Type", "Authorization").
		AllowCredentials().
		MaxAge(3600).
		Build()

	// 3. Security Headers Filter
	securityHeadersFilter := filters.ResponseHeaders().
		HSTS(31536000, true, false).
		FrameOptions(filters.FrameOptionDeny).NoSniff().
		ReferrerPolicy(filters.ReferrerPolicyStrictOriginWhenCrossOrigin).
		Build()

	// 4. Authentication & Authorization
	loginForm := security.DefaultLoginForm(security.LoginFormConfiguration{
		Action: "/login",
		Title:  "Task Manager - Login",
	})

	authProvider := security.LoginFormAuthenticationProvider(users...).
		LoginForm(loginForm).Required(true).RedirectToForm(true).
		DefaultAuthenticatedRedirectionPath("/app").
		Build()

	securityFilter := security.Filter(false).
		// App pages - requires authentication
		Path("/app/**").Authentication(authProvider).Authorize().
		// API - requires user scope
		Path("/api/tasks/**").Authentication(authProvider).Authorize(security.Scope("user")).
		// Admin API - requires admin scope
		Path("/api/admin/**").Authentication(authProvider).Authorize(security.Scope("admin")).
		Build()

	engine := we.New().
		SessionManager(sessionManager).
		Filter(corsFilter).
		Filter(securityHeadersFilter).
		Filter(securityFilter).
		Handle("/", home).                              // Public home page
		Handle("/api/health", health).                  // Health check endpoint
		Handle("/app", app).                            // App dashboard
		Handle("/logout", logout).                      // log out
		HandleMethod("GET", "/api/tasks", list).        // API: List tasks
		HandleMethod("POST", "/api/tasks", create).     // API: Create task
		HandleMethod("PUT", "/api/tasks/{id}", update). // API: Update task
		HandleMethod("DELETE", "/api/tasks/{id}", del). // API: Delete task
		Handle("/api/admin/users", admin).              // Admin: List all users (admin only)
		Build()

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
