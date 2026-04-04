# OAuth2/OpenID Connect Example

This example demonstrates the configuration pattern for integrating OAuth2/OpenID Connect providers.

## Important Note

**This is a configuration example.** To use OAuth2/OIDC authentication, you need to:

1. Register an application with an OAuth2 provider
2. Obtain client credentials (client ID and secret)
3. Configure redirect URIs
4. Update the code with your credentials

## Configuration

```go
// Example with Google
oidcProvider := security.OpenIdIdentityProvider().
    Issuer("https://accounts.google.com").
    ClientId("your-client-id.apps.googleusercontent.com").
    ClientSecret("your-client-secret").
    RedirectHandler("/auth/callback").
    Scopes("openid", "profile", "email").
    Build()

authProvider := security.SSOAuthenticationProvider(oidcProvider).
    LoginPath("/login").
    Build()

securityFilter := security.Filter(false).
    Path("/app/**").
        Authentication(authProvider).
        Authorize().
    Build()
```

## Common Providers

- **Google**: https://accounts.google.com
- **Microsoft**: https://login.microsoftonline.com/{tenant}/v2.0  
- **Okta**: https://{domain}.okta.com
- **Auth0**: https://{domain}.auth0.com

## Required Configuration

1. **Issuer**: OIDC provider's base URL
2. **Client ID**: From provider's app registration
3. **Client Secret**: From provider's app registration  
4. **Redirect Handler**: Path for OAuth callback (must match provider config)
5. **Scopes**: At minimum `openid`, plus `profile`, `email`, etc.

## Authentication Flow

1. User accesses protected resource
2. Redirected to provider's login page
3. User authenticates
4. Provider redirects to callback URL
5. App validates token and creates session
6. User accesses protected resources

## Session Requirement

OAuth2/OIDC **requires sessions**:

```go
engine.SetSessionManager(we.DefaultSessionManager().Build())
```

## Next Steps

- [09-mtls-auth](../09-mtls-auth/) - Mutual TLS authentication
- [10-authorization](../10-authorization/) - Authorization patterns
