# Authorization & RBAC Example

Demonstrates Role-Based Access Control (RBAC) with scope-based authorization.

## Running

```bash
go run main.go
```

## User Roles

| Username | Password   | Scopes              | Access Level |
|----------|------------|---------------------|--------------|
| admin    | admin123   | admin, editor, viewer | Full access  |
| editor   | editor123  | editor, viewer      | Edit & View  |
| viewer   | viewer123  | viewer              | View only    |
| guest    | guest123   | (none)              | Public only  |

## Access Control Matrix

| Endpoint      | Required Scope | admin | editor | viewer | guest |
|---------------|----------------|-------|--------|--------|-------|
| /public/**    | (anonymous)    | ✓     | ✓      | ✓      | ✓     |
| /view/**      | viewer         | ✓     | ✓      | ✓      | ✗     |
| /edit/**      | editor         | ✓     | ✓      | ✗      | ✗     |
| /admin/**     | admin          | ✓     | ✗      | ✗      | ✗     |
| /api/write/** | editor OR admin| ✓     | ✓      | ✗      | ✗     |

## Try It

```bash
# View with viewer credentials (succeeds)
curl -u viewer:viewer123 http://localhost:8080/view/dashboard

# Edit with viewer credentials (fails - 403 Forbidden)
curl -u viewer:viewer123 http://localhost:8080/edit/content

# Edit with editor credentials (succeeds)
curl -u editor:editor123 http://localhost:8080/edit/content

# Admin with editor credentials (fails - 403 Forbidden)
curl -u editor:editor123 http://localhost:8080/admin/users

# Admin with admin credentials (succeeds)
curl -u admin:admin123 http://localhost:8080/admin/users
```

## Key Concepts

### Scope-Based Authorization

```go
.Path("/admin/**").
    Authentication(authProvider).
    Authorize(security.Scope("admin"))
```

### Multiple Authorization Rules

**Require ALL scopes:**
```go
.Authorize(security.All(
    security.Scope("admin"),
    security.Scope("premium"),
))
```

**Require ANY scope:**
```go
.Authorize(security.Either(
    security.Scope("editor"),
    security.Scope("admin"),
))
```

### Custom Authorization

```go
customAuth := security.AuthorizationFunc(func(u *security.User, s we.RequestScope) bool {
    return u.Username == "superadmin"
})

.Authorize(customAuth)
```

## Authorization Types

- `Scope(string)` - Check user has scope
- `Method(string)` - Check HTTP method
- `Realm(string)` - Check authentication realm
- `Origin(string)` - Check authentication origin
- `All(...)` - Require all authorizations
- `Either(...)` - Require any authorization
- `AuthorizationFunc(...)` - Custom logic

## Next Steps

- [11-error-handling](../11-error-handling/) - Error handling patterns
- [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) - Security best practices
