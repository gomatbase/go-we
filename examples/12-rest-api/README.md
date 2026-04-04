# REST API with JSON Example

A complete RESTful API example with JSON request/response handling and CRUD operations.

## Running

```bash
go run main.go
```

## API Endpoints

| Method | Endpoint          | Description       |
|--------|-------------------|-------------------|
| GET    | /api/users        | List all users    |
| GET    | /api/users/{id}   | Get user by ID    |
| POST   | /api/users        | Create new user   |
| PUT    | /api/users/{id}   | Update user       |
| DELETE | /api/users/{id}   | Delete user       |

## cURL Examples

### List Users
```bash
curl http://localhost:8080/api/users
```

### Get User
```bash
curl http://localhost:8080/api/users/1
```

### Create User
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"David","email":"david@example.com"}'
```

### Update User
```bash
curl -X PUT http://localhost:8080/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice Updated","email":"alice.new@example.com"}'
```

### Delete User
```bash
curl -X DELETE http://localhost:8080/api/users/3
```

## Key Concepts

### JSON Request Parsing

```go
body, _ := io.ReadAll(scope.Request().Body)
var user User
json.Unmarshal(body, &user)
```

### JSON Response

```go
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(user)
```

### HTTP Status Codes

- `200 OK` - Successful GET, PUT
- `201 Created` - Successful POST
- `204 No Content` - Successful DELETE
- `400 Bad Request` - Validation errors
- `404 Not Found` - Resource not found

### Error Handling

```go
if newUser.Name == "" {
    return events.New(400, "Name is required")
}
```

## Best Practices

1. **Content-Type**: Always set `Content-Type: application/json`
2. **Status Codes**: Use appropriate HTTP status codes
3. **Validation**: Validate input before processing
4. **Error Messages**: Return clear error messages
5. **Idempotency**: PUT and DELETE are idempotent

## Next Steps

- [13-static-files](../13-static-files/) - Serving static files
- [14-full-application](../14-full-application/) - Complete application
