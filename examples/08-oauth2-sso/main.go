// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gomatbase/go-we"
)

func main() {
	engine := we.New()

	// Enable session management (required for OAuth2/OIDC)
	sessionManager := we.DefaultSessionManager().
		SessionTimeout(1 * time.Hour).
		CookieName("session_id").
		CookieSecure(false). // Set to true in production
		CookieHttpOnly(true).
		Build()
	engine.SetSessionManager(sessionManager)

	// Placeholder home page with configuration example
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")

		fmt.Fprint(w, `
		<h1>OAuth2/OpenID Connect Example</h1>
		
		<h2>Important Note</h2>
		<p><strong>This example demonstrates the configuration pattern for OAuth2/OIDC integration.</strong></p>
		<p>To run this example, you need to:</p>
		<ol>
			<li>Register an application with an OAuth2 provider (Google, Azure AD, etc.)</li>
			<li>Obtain client ID and client secret</li>
			<li>Configure the redirect URI in your OAuth2 provider settings</li>
			<li>Update the configuration in main.go with your credentials</li>
		</ol>

		<h2>Configuration Example</h2>
		<pre>
// Configure OpenID Connect provider (e.g., Google)
oidcProvider := security.OpenIdIdentityProvider().
    Issuer("https://accounts.google.com").
    ClientId("your-client-id.apps.googleusercontent.com").
    ClientSecret("your-client-secret").
    RedirectHandler("/auth/callback").
    Scopes("openid", "profile", "email").
    Build()

// Create SSO authentication provider
authProvider := security.SSOAuthenticationProvider(oidcProvider).
    LoginPath("/login").
    Build()

// Configure security filter
securityFilter := security.Filter(false).
    Path("/app/**").
        Authentication(authProvider).
        Authorize().
    Build()

engine.AddFilter(securityFilter)
		</pre>

		<h2>Common OIDC Providers</h2>
		<ul>
			<li><strong>Google:</strong> https://accounts.google.com</li>
			<li><strong>Microsoft Azure AD:</strong> https://login.microsoftonline.com/{tenant}/v2.0</li>
			<li><strong>Okta:</strong> https://{your-domain}.okta.com</li>
			<li><strong>Auth0:</strong> https://{your-domain}.auth0.com</li>
		</ul>

		<h2>Flow</h2>
		<ol>
			<li>User accesses protected resource</li>
			<li>Redirected to OAuth2 provider's login page</li>
			<li>User authenticates with provider</li>
			<li>Provider redirects back to callback URL</li>
			<li>Application validates token and creates session</li>
			<li>User gains access to protected resources</li>
		</ol>

		<h2>Required Scopes</h2>
		<p>At minimum, request <code>openid</code> scope. Common additional scopes:</p>
		<ul>
			<li><code>profile</code> - User's profile information</li>
			<li><code>email</code> - User's email address</li>
			<li><code>offline_access</code> - Refresh tokens (if supported)</li>
		</ul>
		`)
		return nil
	})

	fmt.Println("OAuth2/OIDC Example")
	fmt.Println("This example requires configuration with an OAuth2 provider.")
	fmt.Println("See the source code and README.md for configuration details.")
	fmt.Println()
	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
