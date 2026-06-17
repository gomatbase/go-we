// Copyright 2023-2026 GOM. All rights reserved.
// Since 29/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

type dummyAuthorizationCodeProvider struct {
	state string
	user  *security.User
	e     error
}

func (dacp *dummyAuthorizationCodeProvider) AuthorizationUrl(_, state string) string {
	dacp.state = state
	return "https://openid.com"
}

func (dacp *dummyAuthorizationCodeProvider) State(_ *http.Request) (state string, accessCode string) {
	return dacp.state, "accessCode"
}

func (dacp *dummyAuthorizationCodeProvider) ValidateAuthorizationCode(_ context.Context, _, _ string) (*security.User, error) {
	return dacp.user, dacp.e
}

func TestSSOAuthenticationProviderBuilder(t *testing.T) {
	t.Run("Test successful build", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("standard sso provider with authorization code should not fail : %v", r)
			}
		}()
		provider := security.SSOAuthenticationProvider().AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
		if provider.Realm() != security.SSORealm {
			t.Errorf("realm should be %s, instead it's : %s", security.SSORealm, provider.Realm())
		} else if provider.Challenge() != "" {
			t.Error("sso provider should have no challenge")
		}
		provider = security.SSOAuthenticationProvider().Realm("realm").AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
		if provider.Realm() != "realm" {
			t.Errorf("realm should be realm, instead it's : %s", provider.Realm())
		} else if provider.Challenge() != "" {
			t.Error("sso provider should have no challenge")
		}
		provider = security.SSOAuthenticationProvider().AuthorizationReplyHandler("sso").AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
	})
	t.Run("Test missing authorization code provider", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("sso provider without an authorization code provider should fail")
			}
		}()
		security.SSOAuthenticationProvider().Build()
	})
	t.Run("Test setting an invalid authorization code provider", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("sso provider without an authorization code provider should fail")
			}
		}()
		security.SSOAuthenticationProvider().AuthorizationCodeProvider(nil).Build()
	})
	t.Run("Test setting an invalid realm", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("realm cannot be empty, should fail")
			}
		}()
		security.SSOAuthenticationProvider().Realm("").Build()
	})
	t.Run("Test empty code reply handler", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("empty authorization code reply handler should result in failure")
			}
		}()
		security.SSOAuthenticationProvider().AuthorizationReplyHandler("").AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
	})
	t.Run("Test invalid code reply handler", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("invalid authorization code reply handler should result in failure")
			}
		}()
		security.SSOAuthenticationProvider().AuthorizationReplyHandler("/").AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
	})
	t.Run("Test invalid default authenticated endpoint", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("invalid default authenticated endpoint should result in failure")
			}
		}()
		security.SSOAuthenticationProvider().DefaultAuthenticatedEndpoint("").AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
	})
}

func TestSSOAuthenticationProvider(t *testing.T) {
	t.Run("Test is valid", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).Build()
		if provider.IsValid(nil) {
			t.Error("nil users should always be invalid")
		}
		if !provider.IsValid(&security.User{}) {
			t.Error("session check should always return true")
		}
	})
	t.Run("Test successful authorization code handling", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{user: &security.User{Username: "user1"}}).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/somewhere?param=value&param=anothervalue")
		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Authentication should have failed")
		} else if !events.FoundRedirect.Is(e) {
			t.Error("expected a redirection event")
		} else if e.(events.WeEvent).Attribute() != "https://openid.com" {
			t.Errorf("should redirect to https://openid.com : %s", headers.Get("Location"))
		} else if user != nil {
			t.Errorf("user should be nil : %v", user)
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization")
		if user, e := provider.Authenticate(headers, scope); !events.FoundRedirect.Is(e) {
			t.Error("Authentication should have succeeded with a redirect to the original point of origin")
		} else if user == nil {
			t.Error("user should not be nil")
		} else if !strings.HasPrefix(e.(events.WeEvent).Attribute(), "http://localhost:8080/somewhere?") {
			t.Errorf("content-location should point to original endpoint : %s", e.(events.WeEvent).Attribute())
		} else if user.Username != "user1" {
			t.Errorf("unexpected username : %v", user.Username)
		}
	})
	t.Run("Test successful authorization code handling calling the authorization point", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{user: &security.User{Username: "user1"}}).
			DefaultAuthenticatedEndpoint("root").
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization?param=value&param=anothervalue")
		if user, e := provider.Authenticate(headers, scope); !events.FoundRedirect.Is(e) {
			t.Error("Authentication should have failed and redirected to sso endpoint")
		} else if e.(events.WeEvent).Attribute() != "https://openid.com" {
			t.Errorf("should redirect to https://openid.com : %s", e.(events.WeEvent).Attribute())
		} else if user != nil {
			t.Errorf("user should be nil : %v", user)
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization")
		if user, e := provider.Authenticate(headers, scope); !events.FoundRedirect.Is(e) {
			t.Error("Authentication should have succeeded with redirection to root endpoint")
		} else if user == nil {
			t.Error("user should not be nil")
		} else if !strings.HasPrefix(e.(events.WeEvent).Attribute(), "http://localhost:8080/root") {
			t.Errorf("content-location should point to default endpoint : %s", headers.Get("Content-Location"))
		} else if user.Username != "user1" {
			t.Errorf("unexpectedt username : %v", user.Username)
		}
	})

	t.Run("Test failed authorization code check", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{user: &security.User{Username: "user1"}, e: events.UnauthorizedError}).
			DefaultAuthenticatedEndpoint("/root").
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization?param=value&param=anothervalue")
		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Authentication should have failed")
		} else if !events.FoundRedirect.Is(e) {
			t.Error("expected a redirection event")
		} else if e.(events.WeEvent).Attribute() != "https://openid.com" {
			t.Errorf("should redirect to https://lopenid.com0 : %s", headers.Get("Location"))
		} else if user != nil {
			t.Errorf("user should be nil : %v", user)
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization")
		if user, e := provider.Authenticate(headers, scope); e != events.UnauthorizedError {
			t.Error("Authentication should have failed")
		} else if user != nil {
			t.Error("user should be nil")
		}
	})

	t.Run("Test failed authorization code check returning no user", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{}).
			DefaultAuthenticatedEndpoint("/root").
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization?param=value&param=anothervalue")
		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Authentication should have failed")
		} else if !events.FoundRedirect.Is(e) {
			t.Error("expected a redirection event")
		} else if e.(events.WeEvent).Attribute() != "https://openid.com" {
			t.Errorf("should redirect to https://lopenid.com0 : %s", headers.Get("Location"))
		} else if user != nil {
			t.Errorf("user should be nil : %v", user)
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization")
		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Authentication should have failed")
		} else if user != nil {
			t.Error("user should be nil")
		} else if headers.Get("Content-Location") != "" {
			t.Errorf("content-location should be emptyt : %s", headers.Get("Content-Location"))
		}
	})
}

// mockAuthCodeProvider is a mock AuthorizationCodeProvider for SSO coverage tests
type mockAuthCodeProvider struct{}

func (m *mockAuthCodeProvider) AuthorizationUrl(replyHandlerUrl, state string) string {
	return "http://auth-server/authorize?redirect_uri=" + replyHandlerUrl + "&state=" + state
}

func (m *mockAuthCodeProvider) State(r *http.Request) (string, string) {
	q := r.URL.Query()
	return q.Get("state"), q.Get("code")
}

func (m *mockAuthCodeProvider) ValidateAuthorizationCode(_ context.Context, code, replyHandlerUrl string) (*security.User, error) {
	return &security.User{Username: "sso-user"}, nil
}

// TestCoverageSSODynamicAddress tests SSOAuthenticationProvider DynamicAddress builder
func TestCoverageSSODynamicAddress(t *testing.T) {
	t.Run("DynamicAddress sets dynamic base url", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		if provider == nil {
			t.Error("Expected provider to be built successfully")
		}
	})
}

// TestCoverageSSORedirectToRequestedUrl tests SSOAuthenticationProvider RedirectToRequestedUrl builder
func TestCoverageSSORedirectToRequestedUrl(t *testing.T) {
	t.Run("RedirectToRequestedUrl configures redirect behavior", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			RedirectToRequestedUrl(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		if provider == nil {
			t.Error("Expected provider to be built successfully")
		}
	})

	t.Run("RedirectToRequestedUrl false uses chaining", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			RedirectToRequestedUrl(false).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		if provider == nil {
			t.Error("Expected provider to be built successfully")
		}
	})
}

// TestCoverageSSOAddress tests SSOAuthenticationProvider Address builder
func TestCoverageSSOAddress(t *testing.T) {
	t.Run("Address sets the public address", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			Address("https://example.com").
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		if provider == nil {
			t.Error("Expected provider to be built successfully")
		}
	})

	t.Run("Address panics with empty address", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with empty address")
			}
		}()
		security.SSOAuthenticationProvider().
			Address("").
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()
	})

	t.Run("Address panics with invalid url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with invalid url")
			}
		}()
		security.SSOAuthenticationProvider().
			Address("://invalid").
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()
	})

	t.Run("Address panics with opaque url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with opaque url")
			}
		}()
		security.SSOAuthenticationProvider().
			Address("mailto:user@example.com").
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()
	})
}

// TestCoverageSSOEndpoints tests SSOAuthenticationProvider Endpoints()
func TestCoverageSSOEndpoints(t *testing.T) {
	provider := security.SSOAuthenticationProvider().
		AuthorizationCodeProvider(&mockAuthCodeProvider{}).
		Build()

	endpoints := provider.Endpoints()
	if endpoints == nil || len(endpoints) == 0 {
		t.Error("Expected SSO provider to return reply handler endpoint")
	}
	if endpoints[0] != "/sso/authorization" {
		t.Errorf("Expected default endpoint '/sso/authorization', got: %s", endpoints[0])
	}
}

// TestCoverageSSOAuthenticateRedirect tests the SSO authenticate flow that triggers extractSchemaAndHost
func TestCoverageSSOAuthenticateRedirect(t *testing.T) {
	t.Run("SSO redirects to authorization URL with Forwarded header", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		scope.SetHeader("Forwarded", "proto=https;host=example.com")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})

	t.Run("SSO redirects with X-Forwarded-Host header", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		scope.SetHeader("X-Forwarded-Host", "proxy.example.com")
		scope.SetHeader("X-Forwarded-Proto", "https")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})

	t.Run("SSO redirects with X-Forwarded-Proto only", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		scope.SetHeader("X-Forwarded-Proto", "https")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})

	t.Run("SSO redirects without forwarded headers", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})

	t.Run("SSO with static address does not use dynamic", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			Address("https://static.example.com").
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})

	t.Run("SSO with X-Forwarded-Host without proto defaults to https", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		scope.SetHeader("X-Forwarded-Host", "proxy.example.com")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})

	t.Run("SSO with Forwarded header missing proto defaults to https", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			DynamicAddress(true).
			AuthorizationCodeProvider(&mockAuthCodeProvider{}).
			Build()

		filter := security.Filter(true).
			Authentication(provider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/protected")
		scope.SetHeader("Forwarded", "host=example.com")
		e := filter.Filter(headers, scope)
		if e == nil {
			t.Error("Expected redirect error from SSO")
		}
	})
}
