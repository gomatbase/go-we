// Copyright 2023 GOM. All rights reserved.
// Since 17/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/errors"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

type dummyAuthorization struct {
	result bool
	check  func(*security.User, we.RequestScope) bool
}

func (d *dummyAuthorization) IsAuthorized(user *security.User, scope we.RequestScope) bool {
	if d.check == nil {
		return d.result
	}
	return d.check(user, scope)
}

type dummyProvider struct {
	realm               string
	challenge           string
	authenticatedUser   *security.User
	authenticationError error
	authenticate        func(http.Header, we.RequestScope) (*security.User, error)
	valid               bool
	isValid             func(*security.User) bool
}

func (dp *dummyProvider) Authenticate(headers http.Header, scope we.RequestScope) (*security.User, error) {
	if dp.authenticate != nil {
		return dp.authenticate(headers, scope)
	}
	return dp.authenticatedUser, dp.authenticationError
}

func (dp *dummyProvider) Realm() string {
	return dp.realm
}

func (dp *dummyProvider) IsValid(user *security.User) bool {
	if dp.isValid != nil {
		return dp.isValid(user)
	}
	return dp.valid
}

func (dp *dummyProvider) Challenge() string {
	return dp.challenge
}

func TestFilterBuilds(t *testing.T) {
	t.Run("Test empty builder", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Building an empty filter should fail")
			}
		}()
		security.Filter(security.DefaultAnonymousAccess).Build()
	})
	t.Run("Test empty Paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding empty paths should fail")
			}
		}()
		security.Filter(security.DefaultAnonymousAccess).Path().Anonymous().Build()
	})
	t.Run("Test empty authentications", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding empty authentications should fail")
			}
		}()
		security.Filter(security.DefaultAnonymousAccess).Authentication().Build()
	})
	t.Run("Test authorizations with no authentication", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding authorizations with no authentication should fail")
			}
		}()
		security.Filter(security.DefaultAnonymousAccess).Path("/something").Authorize(&dummyAuthorization{result: true}).Build()
	})
	t.Run("Test overloading realms at root authentication", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding multiple providers under the same realm should fail")
			}
		}()
		provider1 := &dummyProvider{realm: "realm1"}
		provider2 := &dummyProvider{realm: "realm1"}
		security.Filter(security.DefaultAnonymousAccess).Authentication(provider1, provider2).Build()
	})
	t.Run("Test overloading root realms", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding path provider overloading root providers should fail")
			}
		}()
		provider1 := &dummyProvider{realm: "realm1"}
		provider2 := &dummyProvider{realm: "realm1"}
		security.Filter(security.DefaultAnonymousAccess).Authentication(provider1).
			Path("/").Authentication(provider2).Authorize().
			Build()
	})
	t.Run("Test nil providers", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding nil providers should fail")
			}
		}()
		provider := &dummyProvider{realm: "realm1"}
		security.Filter(security.DefaultAnonymousAccess).Authentication(provider, nil).Build()
	})
	t.Run("Test path nil providers", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding nil path providers should fail")
			}
		}()
		provider := &dummyProvider{realm: "realm1"}
		security.Filter(security.DefaultAnonymousAccess).Path("/").Authentication(provider, nil).Authorize().Build()
	})
	t.Run("Test providers without realm", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding providers without realm should fail")
			}
		}()
		provider := &dummyProvider{realm: ""}
		security.Filter(security.DefaultAnonymousAccess).Authentication(provider).Build()
	})
	t.Run("Test path providers without realm", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Adding path providers without realm should fail")
			}
		}()
		provider := &dummyProvider{realm: ""}
		security.Filter(security.DefaultAnonymousAccess).Path("/").Authentication(provider).Authorize().Build()
	})
	t.Run("Test overloading authorization paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("overloading authorization paths should fail")
			}
		}()
		provider := &dummyProvider{realm: "realm"}
		security.Filter(security.DefaultAnonymousAccess).Path("/", "/").Authentication(provider).Authorize().Build()
	})
	t.Run("Test overloading authorizations", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("overloading authorization paths should fail")
			} else {
				fmt.Println(r)
			}
		}()
		provider1 := &dummyProvider{realm: "realm1"}
		provider2 := &dummyProvider{realm: "realm2"}
		security.Filter(security.DefaultAnonymousAccess).
			Path("/").Authentication(provider1).Authorize().
			Path("/").Authentication(provider2).Authorize().
			Build()
	})
	t.Run("Test overloading anonymous paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("overloading anonymous paths should not fail")
			}
		}()
		security.Filter(security.DefaultAnonymousAccess).Path("/", "/").Authorize().Build()
	})
	t.Run("Test Path authorizations with empty providers", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("adding empty list of authentication providers to path authorization should fail")
			}
		}()
		security.Filter(security.DefaultAnonymousAccess).Path("/").Authentication().Authorize().Build()
	})
	t.Run("Test Anonymous access with path authentication", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("adding authenticators for anonyous path should fail")
			}
		}()
		security.Filter(security.DefaultAuthenticatedAccess).Path("/").Authentication(&dummyProvider{realm: "realm"}).Anonymous().Build()
	})
}

func TestFilterRootAuthentication(t *testing.T) {
	t.Run("Test unrestricted unauthenticated call", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"}
		filter := security.Filter(security.DefaultAnonymousAccess).Authentication(provider).Build()
		if e := filter.Filter(nil, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e != nil {
			t.Errorf("Unexpected error for unauthenticated call in unrestricted filter: %v", e)
		}
	})
	t.Run("Test restricted unauthenticated call without challenges", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted filter should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted filter: %v", e)
		} else if len(headers["WWW-Authenticate"]) > 0 {
			t.Errorf("Unexpected challenge for unauthenticated call in restricted filter: %s", headers["WWW-Authenticate"][0])
		}
	})
	t.Run("Test restricted unauthenticated call with challenges", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", challenge: "Basic"}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted filter should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted filter: %v", e)
		} else if len(headers["Www-Authenticate"]) == 0 {
			t.Error("Expected challenges for unauthenticated call")
		} else if len(headers["Www-Authenticate"]) > 1 {
			t.Errorf("More authentication challenges than expected: %v", headers["Www-Authenticate"])
		} else if headers.Get("WWW-Authenticate") != "Basic realm=\"realm\"" {
			t.Errorf("Unexpected challenge for unauthenticated call in restricted filter: %s", headers["Www-Authenticate"][0])
		}
	})
	t.Run("Test restricted unauthenticated call with multiple challenges", func(t *testing.T) {
		provider1 := &dummyProvider{realm: "realm1", challenge: "Basic"}
		provider2 := &dummyProvider{realm: "realm2", challenge: "Bearer"}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider1, provider2).Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted filter should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted filter: %v", e)
		} else if len(headers["Www-Authenticate"]) == 0 {
			t.Error("Expected challenges for unauthenticated call")
		} else if len(headers["Www-Authenticate"]) != 2 {
			t.Errorf("2 authentication challenges: %v", headers["Www-Authenticate"])
		} else if headers["Www-Authenticate"][0] != "Basic realm=\"realm1\"" || headers["Www-Authenticate"][1] != "Bearer realm=\"realm2\"" {
			// Challenges are ordered by provider order
			t.Errorf("Unexpected challenges for unauthenticated call in restricted filter: %s, %s", headers["Www-Authenticate"][0], headers["Www-Authenticate"][1])
		}
	})
	t.Run("Test session authenticated call", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", valid: true}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetInSession(security.UserAttributeName, &security.User{Realm: "realm"})
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
		}
	})
	t.Run("Test invalid session authenticated call", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", valid: false}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetInSession(security.UserAttributeName, &security.User{Realm: "realm"})
		if e := filter.Filter(headers, scope); e != errors.UnauthorizedError {
			t.Errorf("Expected user to be unauthorized, instead got error: %v", e)
		}
	})
	t.Run("Test failed authenticated call", func(t *testing.T) {
		// Using a different weError to check if it's getting the provider error
		provider := &dummyProvider{realm: "realm", authenticationError: errors.OKInterruption}
		filter := security.Filter(security.DefaultAnonymousAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != errors.OKInterruption {
			t.Errorf("Expected user to fail authentication, instead got error: %v", e)
		}
	})
	t.Run("Test successful anonymous access", func(t *testing.T) {
		// Using a different weError to check if it's getting the provider error
		provider := &dummyProvider{realm: "realm", authenticatedUser: security.Anonymous}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user suceed in authentication, instead got error: %v", e)
		} else if scope.Get(security.UserAttributeName) != nil {
			t.Error("anonymous users should not be present in the request scope")
		} else if scope.GetFromSession(security.UserAttributeName) != nil {
			t.Error("anonymous users should not be present in the session")
		}
	})
	t.Run("Test successful authenticated access", func(t *testing.T) {
		// Using a different weError to check if it's getting the provider error
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "username"}}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user suceed in authentication, instead got error: %v", e)
		} else if user := scope.Get(security.UserAttributeName); user == nil || user.(*security.User).Username != "username" {
			t.Errorf("Expected authenticated user to be present in request, instead got: %v", user)
		} else if user = scope.GetFromSession(security.UserAttributeName); user == nil || user.(*security.User).Username != "username" {
			t.Errorf("Expected authenticated user to be present in session, instead got: %v", user)
		} else if user.(*security.User).Realm != "realm" {
			t.Errorf("Expected authenticated user to have the realm attributed, instead got: %v", user.(*security.User).Realm)
		}
	})
}

func TestFilterPathAuthentication(t *testing.T) {
	t.Run("Test unauthenticated call to unrestricted path", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"}
		filter := security.Filter(security.DefaultAnonymousAccess).
			Path("/*").Authentication(provider).Authorize().
			Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e != nil {
			t.Errorf("Call for unrestricted path should not fail. %v", e)
		}
	})
	t.Run("Test unauthenticated call to restricted path without challenges", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"}
		filter := security.Filter(security.DefaultAnonymousAccess).
			Path("/", "/*").Authentication(provider).Authorize().
			Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted restricted path should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted filter: %v", e)
		} else if len(headers["WWW-Authenticate"]) > 0 {
			t.Errorf("Unexpected challenge for unauthenticated call in restricted filter: %s", headers["WWW-Authenticate"][0])
		}
	})
	t.Run("Test unauthenticated call to restricted path with challenges", func(t *testing.T) {
		provider1 := &dummyProvider{realm: "realm1"}
		provider2 := &dummyProvider{realm: "realm2", challenge: "Basic"}
		filter := security.Filter(security.DefaultAnonymousAccess).
			Path("/", "/*").Authentication(provider2).Authorize().
			Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted restricted path should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted call: %v", e)
		} else if len(headers["Www-Authenticate"]) == 0 {
			t.Error("Expected challenges for unauthenticated call")
		} else if len(headers["Www-Authenticate"]) > 1 {
			t.Errorf("More authentication challenges than expected: %v", headers["Www-Authenticate"])
		} else if headers.Get("WWW-Authenticate") != "Basic realm=\"realm2\"" {
			t.Errorf("Unexpected challenge for unauthenticated call in restricted filter: %s", headers["Www-Authenticate"][0])
		}
		filter = security.Filter(security.DefaultAnonymousAccess).
			Authentication(provider1).
			Path("/", "/*").Authentication(provider2).Authorize().
			Build()
		headers = make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted restricted path should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted call: %v", e)
		} else if len(headers["Www-Authenticate"]) == 0 {
			t.Error("Expected challenges for unauthenticated call")
		} else if len(headers["Www-Authenticate"]) > 1 {
			t.Errorf("More authentication challenges than expected: %v", headers["Www-Authenticate"])
		} else if headers.Get("WWW-Authenticate") != "Basic realm=\"realm2\"" {
			t.Errorf("Unexpected challenge for unauthenticated call in restricted filter: %s", headers["Www-Authenticate"][0])
		}
		provider1 = &dummyProvider{realm: "realm1", challenge: "Bearer"}
		filter = security.Filter(security.DefaultAnonymousAccess).
			Authentication(provider1).
			Path("/", "/*").Authentication(provider2).Authorize().
			Build()
		headers = make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted restricted path should fail")
		} else if !e.(errors.WeError).Is(errors.UnauthorizedError) {
			t.Errorf("Unexpected error for unauthenticated call in restricted call: %v", e)
		} else if len(headers["Www-Authenticate"]) != 2 {
			t.Error("Expected 2 challenges for unauthenticated call")
		} else if headers["Www-Authenticate"][0] != "Basic realm=\"realm2\"" || headers["Www-Authenticate"][1] != "Bearer realm=\"realm1\"" {
			// Challenges are ordered by provider order
			t.Errorf("Unexpected challenges from path and then root authentication providers: %s, %s", headers["Www-Authenticate"][0], headers["Www-Authenticate"][1])
		}
	})
	t.Run("Test session authenticated call to authorized path", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", valid: true}
		filter := security.Filter(security.DefaultAuthenticatedAccess).
			Path("/").Authentication(provider).Authorize().
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetInSession(security.UserAttributeName, &security.User{Realm: "realm"})
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
		}
	})
	t.Run("Test session authenticated call to unauthorized path", func(t *testing.T) {
		sessionUser := &security.User{Realm: "realm1"}
		authenticatedUser := &security.User{Realm: "realm1"}
		provider1 := &dummyProvider{realm: "realm1", valid: false, authenticationError: errors.OKInterruption}
		provider2 := &dummyProvider{realm: "realm2", authenticationError: errors.BadRequestError}
		filter := security.Filter(security.DefaultAuthenticatedAccess).
			Authentication(provider1).
			Path("/").Authentication(provider2).Authorize(security.Realm("realm2")).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetInSession(security.UserAttributeName, sessionUser)
		if e := filter.Filter(headers, scope); e == nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
		} else if e != errors.OKInterruption {
			t.Errorf("Expected error coming from root authentication, instead got error: %v", e)
		} else if scope.GetFromSession(security.UserAttributeName) != nil {
			t.Errorf("Expected session user to to be cleared, instead got: %v", scope.GetFromSession(security.UserAttributeName))
		}
		provider1.authenticationError = nil
		provider1.valid = true
		scope.SetInSession(security.UserAttributeName, sessionUser)
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to not be authorized")
		} else if e != errors.BadRequestError {
			t.Errorf("Expected error coming from path authentication, instead got error: %v", e)
		} else if scope.GetFromSession(security.UserAttributeName) != sessionUser {
			t.Errorf("Expected session user to remain the same, instead got: %v", scope.GetFromSession(security.UserAttributeName))
		}
		provider2.authenticationError = nil
		provider2.authenticatedUser = authenticatedUser
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
		} else if scope.GetFromSession(security.UserAttributeName) != authenticatedUser {
			t.Errorf("Expected session user to to be updated from the new realm, instead got: %v", scope.GetFromSession(security.UserAttributeName))
		}
	})
	t.Run("Test unauthorized path authenticated", func(t *testing.T) {
		provider2 := &dummyProvider{realm: "realm2", authenticatedUser: &security.User{}}
		filter := security.Filter(security.DefaultAuthenticatedAccess).
			Path("/").Authentication(provider2).Authorize(security.Realm("realm2"), security.Origin("somewhere")).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to be not authorized")
		} else if e != errors.ForbiddenError {
			t.Errorf("Expected forbidden error: %v", e)
		}
	})
	t.Run("Test unauthorized root authenticated", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{}}
		filter := security.Filter(security.DefaultAuthenticatedAccess).
			Authentication(provider).
			Path("/").Authorize(security.Realm("realm2")).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e == nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
		} else if e != errors.ForbiddenError {
			t.Errorf("Expected forbidden error: %v", e)
		}
	})
}

func TestFilterAnonymous(t *testing.T) {
	t.Run("Test restricted anonymous call", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticationError: errors.UnauthorizedError}
		filter := security.Filter(security.DefaultAuthenticatedAccess).
			Authentication(provider).
			Path("/somewhere").Anonymous().
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to be not authorized")
		} else if e != errors.UnauthorizedError {
			t.Errorf("Expected unauthorized error: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected anonymous user to be authorized: %v", e)
		}
	})
	t.Run("Test anonymous overriding", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticationError: errors.UnauthorizedError}
		builder := security.Filter(security.DefaultAnonymousAccess)
		filter := builder.
			Path("/somewhere").Anonymous().
			Authentication(provider).
			Path("/somewhere/else/**").Anonymous().
			Path("/", "/**").Authorize(security.Realm("realm")).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to be not authorized")
		} else if e != errors.UnauthorizedError {
			t.Errorf("Expected unauthorized error: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected anonymous user to be authorized: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere/back")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to be not authorized")
		} else if e != errors.UnauthorizedError {
			t.Errorf("Expected unauthorized error: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere/else/out/back")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected anonymous user to be authorized: %v", e)
		}
	})
}
