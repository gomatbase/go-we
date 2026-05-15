# Full Application Example

A complete task manager application demonstrating all major go-we features.

## Running

```bash
go run main.go
```

Visit `http://localhost:8080` and login with:
- **admin** / admin123 (full access)
- **user** / user123 (user access)

## Features Demonstrated

### 1. Session Management
- 30-minute session timeout
- Secure cookie configuration
- Session-based authentication

### 2. Form-Based Authentication
- Custom login form
- Automatic redirect to login
- Session persistence

### 3. Authorization (RBAC)
- User role: Can manage tasks
- Admin role: Can view all users
- Scope-based access control

### 4. RESTful API
- GET /api/tasks - List tasks
- POST /api/tasks - Create task
- PUT /api/tasks/{id} - Update task
- DELETE /api/tasks/{id} - Delete task
- GET /api/admin/users - List users (admin only)

### 5. Security
- CORS filter (configured for http://localhost:3000)
- Security headers (HSTS, X-Frame-Options, etc.)
- HttpOnly cookies
- SameSite cookie protection

### 6. Error Handling
- Validation errors (400)
- Not found errors (404)
- Authorization errors (403)
- JSON error responses

### 7. Frontend Integration
- Single-page application
- REST API consumption
- Dynamic task management

## Architecture

```
┌─────────────────────────────────────────┐
│            Request Flow                 │
├─────────────────────────────────────────┤
│ 1. CORS Filter                          │
│ 2. Security Headers Filter              │
│ 3. Security Filter (Auth + Authz)       │
│ 4. Handler                              │
└─────────────────────────────────────────┘
```

## API Examples

### Create Task
```bash
curl -X POST http://localhost:8080/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title":"My Task","description":"Task description"}' \
  --cookie-jar cookies.txt -u user:user123
```

### List Tasks
```bash
curl http://localhost:8080/api/tasks \
  --cookie cookies.txt
```

### Update Task
```bash
curl -X PUT http://localhost:8080/api/tasks/1 \
  -H "Content-Type: application/json" \
  -d '{"completed":true}' \
  --cookie cookies.txt
```

### Delete Task
```bash
curl -X DELETE http://localhost:8080/api/tasks/1 \
  --cookie cookies.txt
```

### Admin Endpoint
```bash
curl http://localhost:8080/api/admin/users \
  --cookie-jar cookies.txt -u admin:admin123
```

## Code Structure

```go
main()
├── Session Manager Configuration
├── Filter Registration
│   ├── CORS Filter
│   ├── Security Headers Filter
│   └── Security Filter (Auth + Authz)
├── Public Routes
├── Protected App Routes
└── API Routes
    ├── GET /api/tasks
    ├── POST /api/tasks
    ├── PUT /api/tasks/{id}
    ├── DELETE /api/tasks/{id}
    └── GET /api/admin/users (admin only)
```

## Security Configuration

### Session
- 30-minute timeout
- HttpOnly cookies
- SameSite=Lax
- Secure flag (should be true in production with HTTPS)

### CORS
- Allowed origin: http://localhost:3000
- Credentials: true
- Max age: 1 hour

### Headers
- HSTS: 1 year, includeSubDomains
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin

## Production Checklist

- [ ] Enable HTTPS
- [ ] Set `CookieSecure(true)`
- [ ] Use production database instead of in-memory storage
- [ ] Configure proper CORS origins
- [ ] Add rate limiting
- [ ] Implement proper logging
- [ ] Add monitoring/metrics
- [ ] Use environment variables for configuration
- [ ] Enable compression
- [ ] Set up proper error tracking

## Extending This Example

1. **Database**: Replace in-memory storage with PostgreSQL/MySQL
2. **Caching**: Add Redis for session storage
3. **Email**: Add email notifications
4. **File Upload**: Add task attachments
5. **WebSocket**: Add real-time updates
6. **OAuth**: Add OAuth2 providers (Google, GitHub)
7. **API Documentation**: Add OpenAPI/Swagger docs
8. **Testing**: Add unit and integration tests

## Related Examples

- [03-session-management](../03-session-management/) - Session details
- [05-basic-auth](../05-basic-auth/) - Authentication
- [08-authorization](../08-authorization/) - Authorization patterns
- [10-rest-api](../10-rest-api/) - REST API patterns

## Documentation

- [ARCHITECTURE](../../docs/ARCHITECTURE.md) - Framework architecture
- [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) - Production patterns
- [API_DESIGN](../../docs/API_DESIGN.md) - Design philosophy
