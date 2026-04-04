# Bearer Token Authentication Example

Demonstrates Bearer token authentication (commonly used for JWT tokens and API keys).

## Running

```bash
go run main.go
```

## Test Tokens

| Token            | User        | Scopes                    |
|------------------|-------------|---------------------------|
| admin-token-123  | admin       | admin, api:read, api:write|
| user-token-456   | user        | api:read                  |
| app-token-789    | app-service | api:read, api:write       |

## Endpoints

- `/api/public/info` - Public (no auth)
- `/api/read/data` - Requires `api:read` scope
- `/api/write/data` - Requires `api:write` scope
- `/api/admin/users` - Requires `admin` scope

## Try It

```bash
# Public endpoint
curl http://localhost:8080/api/public/info

# Read with user token
curl -H "Authorization: Bearer user-token-456" \
     http://localhost:8080/api/read/data

# Write with app token
curl -H "Authorization: Bearer app-token-789" \
     http://localhost:8080/api/write/data

# Admin endpoint
curl -H "Authorization: Bearer admin-token-123" \
     http://localhost:8080/api/admin/users
```

## Key Concepts

### Token Introspector

Implement the `TokenIntrospector` interface to validate tokens:

```go
type TokenIntrospector interface {
    Introspect(ctx context.Context, token string) (*security.User, error)
}
```

In production, this would validate JWT tokens or call an OAuth2 introspection endpoint.

### Bearer Authentication Provider

```go
authProvider := security.BearerAuthenticationProvider().
    Introspector(myIntrospector).
    Build()
```

## Next Steps

- [07-form-login](../07-form-login/) - Form-based login
- [08-oauth2-sso](../08-oauth2-sso/) - OAuth2/OIDC integration
