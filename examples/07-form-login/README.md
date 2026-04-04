# Form-Based Login Example

Demonstrates form-based authentication with session management and automatic redirect to login page.

## Running

```bash
go run main.go
```

## Test Credentials

| Username | Password  | Scopes |
|----------|-----------|--------|
| admin    | admin123  | admin  |
| user     | user123   | user   |

## How It Works

1. Try to access `/app/dashboard`
2. If not logged in, automatically redirected to login form
3. Enter credentials and submit
4. On success, redirected to dashboard
5. Session maintains authentication state

## Key Concepts

### Login Form Configuration

```go
loginForm := security.DefaultLoginForm(security.LoginFormConfiguration{
    Action: "/login",
    Title:  "Please Login",
})
```

### Form Authentication Provider

```go
authProvider := security.LoginFormAuthenticationProvider(users...).
    LoginForm(loginForm).
    Required(true).
    RedirectToForm(true).
    DefaultAuthenticatedRedirectionPath("/app/dashboard").
    Build()
```

### Session Requirement

Form-based login **requires sessions** to be enabled:

```go
engine.SetSessionManager(we.DefaultSessionManager().Build())
```

## Next Steps

- [08-oauth2-sso](../08-oauth2-sso/) - OAuth2/OpenID Connect
- [10-authorization](../10-authorization/) - Advanced authorization
