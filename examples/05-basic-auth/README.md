# Basic Authentication Example

Demonstrates HTTP Basic Authentication with username/password credentials and scope-based authorization.

## Running

```bash
go run main.go
```

## Test Credentials

| Username | Password  | Scopes      |
|----------|-----------|-------------|
| admin    | admin123  | admin, user |
| user     | user123   | user        |
| guest    | guest123  | (none)      |

## Endpoints

- `/` - Public (no auth)
- `/user/dashboard` - Requires `user` scope
- `/admin/panel` - Requires `admin` scope  
- `/api/data` - Requires authentication (any user)

## Try It

```bash
# Public endpoint
curl http://localhost:8080/

# Admin panel with admin credentials
curl -u admin:admin123 http://localhost:8080/admin/panel

# User dashboard with user credentials
curl -u user:user123 http://localhost:8080/user/dashboard

# API with guest credentials (authenticated but no scopes)
curl -u guest:guest123 http://localhost:8080/api/data
```

## Key Concepts

### Basic Authentication Provider

```go
users := []security.User{
    {Username: "admin", Password: "secret", Scopes: []string{"admin"}},
}

authProvider := security.BasicAuthenticationProvider(users...).Build()
```

### Path-Based Security

```go
securityFilter := security.Filter(false).
    Path("/admin/**").
        Authentication(authProvider).
        Authorize(security.Scope("admin")).
    Build()
```

## Next Steps

- [06-bearer-token](../06-bearer-token/) - Token-based authentication
- [07-form-login](../07-form-login/) - Form-based login
- [10-authorization](../10-authorization/) - Advanced authorization patterns
