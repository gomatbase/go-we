// Copyright 2023 GOM. All rights reserved.
// Since 29/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"net/http"
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

func (dacp *dummyAuthorizationCodeProvider) ValidateAuthorizationCode(_, _ string) (*security.User, error) {
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
		if provider.Realm() != security.DefaultRealm {
			t.Errorf("realm should be %s, instead it's : %s", security.DefaultRealm, provider.Realm())
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
		} else if headers.Get("Location") != "https://openid.com" {
			t.Errorf("should redirect to https://lopenid.com0 : %s", headers.Get("Location"))
		} else if user != nil {
			t.Errorf("user should be nil : %v", user)
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization")
		if user, e := provider.Authenticate(headers, scope); e != nil {
			t.Error("Authentication should have succeeded")
		} else if user == nil {
			t.Error("user should not be nil")
		} else if headers.Get("Content-Location") != "/somewhere?param=value&param=anothervalue" {
			t.Errorf("content-location should point to original endpoint : %s", headers.Get("Content-Location"))
		} else if user.Username != "user1" {
			t.Errorf("unexpectedt username : %v", user.Username)
		}
	})
	t.Run("Test successful authorization code handling calling the authorization point", func(t *testing.T) {
		provider := security.SSOAuthenticationProvider().
			AuthorizationCodeProvider(&dummyAuthorizationCodeProvider{user: &security.User{Username: "user1"}}).
			DefaultAuthenticatedEndpoint("root").
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization?param=value&param=anothervalue")
		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Authentication should have failed")
		} else if !events.FoundRedirect.Is(e) {
			t.Error("expected a redirection event")
		} else if headers.Get("Location") != "https://openid.com" {
			t.Errorf("should redirect to https://lopenid.com0 : %s", headers.Get("Location"))
		} else if user != nil {
			t.Errorf("user should be nil : %v", user)
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/sso/authorization")
		if user, e := provider.Authenticate(headers, scope); e != nil {
			t.Error("Authentication should have succeeded")
		} else if user == nil {
			t.Error("user should not be nil")
		} else if headers.Get("Content-Location") != "/root" {
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
		} else if headers.Get("Location") != "https://openid.com" {
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
		} else if headers.Get("Location") != "https://openid.com" {
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
