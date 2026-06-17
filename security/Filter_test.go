// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
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

func (dp *dummyProvider) Endpoints() []string {
	return nil
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

// testLogger implements we.Logger for testing
type testLogger struct {
	messages []string
}

func (l *testLogger) Debug(msg string) { l.messages = append(l.messages, "[DEBUG] "+msg) }
func (l *testLogger) Info(msg string)  { l.messages = append(l.messages, "[INFO] "+msg) }
func (l *testLogger) Warn(msg string)  { l.messages = append(l.messages, "[WARN] "+msg) }
func (l *testLogger) Error(msg string) { l.messages = append(l.messages, "[ERROR] "+msg) }
func (l *testLogger) Log(level int, msg string) {
	switch level {
	case we.LogLevelDebug:
		l.Debug(msg)
	case we.LogLevelInfo:
		l.Info(msg)
	case we.LogLevelWarn:
		l.Warn(msg)
	case we.LogLevelError:
		l.Error(msg)
	}
}

// dummyProviderWithEndpoints is a provider that reports specific endpoints
type dummyProviderWithEndpoints struct {
	realm        string
	challenge    string
	endpoints    []string
	authenticate func(http.Header, we.RequestScope) (*security.User, error)
}

func (dp *dummyProviderWithEndpoints) Endpoints() []string {
	return dp.endpoints
}

func (dp *dummyProviderWithEndpoints) Authenticate(headers http.Header, scope we.RequestScope) (*security.User, error) {
	if dp.authenticate != nil {
		return dp.authenticate(headers, scope)
	}
	return nil, nil
}

func (dp *dummyProviderWithEndpoints) Realm() string {
	return dp.realm
}

func (dp *dummyProviderWithEndpoints) IsValid(user *security.User) bool {
	return user != nil
}

func (dp *dummyProviderWithEndpoints) Challenge() string {
	return dp.challenge
}

// TestCoverageFilterOnAuthentication tests the OnAuthentication builder method
func TestCoverageFilterOnAuthentication(t *testing.T) {
	t.Run("OnAuthentication panics with no triggers", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when calling OnAuthentication with no triggers")
			}
		}()
		security.Filter(true).Authentication(&dummyProvider{realm: "realm"}).OnAuthentication().Build()
	})

	t.Run("OnAuthentication stores trigger and executes on auth", func(t *testing.T) {
		triggered := false
		var capturedUser *security.User
		trigger := func(user *security.User, scope we.RequestScope) {
			triggered = true
			capturedUser = user
		}

		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "testuser"}}
		filter := security.Filter(true).
			Authentication(provider).
			OnAuthentication(trigger).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if !triggered {
			t.Error("Expected trigger to be called")
		}
		if capturedUser == nil || capturedUser.Username != "testuser" {
			t.Errorf("Expected captured user to be testuser, got: %v", capturedUser)
		}
	})

	t.Run("OnAuthentication with multiple triggers", func(t *testing.T) {
		count := 0
		trigger1 := func(user *security.User, scope we.RequestScope) { count++ }
		trigger2 := func(user *security.User, scope we.RequestScope) { count++ }

		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "testuser"}}
		filter := security.Filter(true).
			Authentication(provider).
			OnAuthentication(trigger1, trigger2).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if count != 2 {
			t.Errorf("Expected both triggers to be called, got count: %d", count)
		}
	})
}

// TestCoverageFilterLogger tests the Logger builder method
func TestCoverageFilterLogger(t *testing.T) {
	t.Run("Logger panics with nil logger", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when calling Logger with nil")
			}
		}()
		security.Filter(true).Authentication(&dummyProvider{realm: "realm"}).Logger(nil).Build()
	})

	t.Run("Logger sets custom logger successfully", func(t *testing.T) {
		logger := &testLogger{}
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "testuser"}}
		filter := security.Filter(true).
			Authentication(provider).
			Logger(logger).
			Build()

		if filter == nil {
			t.Error("Expected filter to be built successfully")
		}
	})

	t.Run("Logger is used when trigger panics", func(t *testing.T) {
		logger := &testLogger{}
		panicTrigger := func(user *security.User, scope we.RequestScope) {
			panic("trigger panic")
		}

		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "testuser"}}
		filter := security.Filter(true).
			Authentication(provider).
			OnAuthentication(panicTrigger).
			Logger(logger).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		// Should not panic - execute recovers and logs
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if len(logger.messages) == 0 {
			t.Error("Expected logger to capture panic message")
		}
	})
}

// TestCoverageExecuteFunction tests the execute function via trigger panic recovery
func TestCoverageExecuteFunction(t *testing.T) {
	t.Run("Execute recovers from trigger panic", func(t *testing.T) {
		logger := &testLogger{}
		panicked := false
		panicTrigger := func(user *security.User, scope we.RequestScope) {
			panicked = true
			panic("intentional panic")
		}

		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "user"}}
		filter := security.Filter(true).
			Authentication(provider).
			OnAuthentication(panicTrigger).
			Logger(logger).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if !panicked {
			t.Error("Expected trigger to have been called")
		}
		found := false
		for _, msg := range logger.messages {
			if msg == "[ERROR] failed to call authentication trigger: intentional panic" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected error log about trigger panic, got: %v", logger.messages)
		}
	})

	t.Run("Execute successful trigger", func(t *testing.T) {
		logger := &testLogger{}
		called := false
		trigger := func(user *security.User, scope we.RequestScope) {
			called = true
		}

		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "user"}}
		filter := security.Filter(true).
			Authentication(provider).
			OnAuthentication(trigger).
			Logger(logger).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if !called {
			t.Error("Expected trigger to have been called")
		}
		if len(logger.messages) != 0 {
			t.Errorf("Expected no error messages, got: %v", logger.messages)
		}
	})
}

// TestCoveragePathBasedAuthorization tests path-based authorization through the filter
func TestCoveragePathBasedAuthorization(t *testing.T) {
	t.Run("Path authorization with authorized user passes", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "admin", Scopes: []string{"admin"}}}
		filter := security.Filter(false).
			Authentication(provider).
			Path("/admin/*").Authorize(security.Scope("admin")).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/admin/dashboard")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected authorized user to pass, got: %v", e)
		}
	})

	t.Run("Path authorization with unauthorized user fails with Forbidden", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "user", Scopes: []string{"basic"}}}
		filter := security.Filter(false).
			Authentication(provider).
			Path("/admin/*").Authorize(security.Scope("admin")).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/admin/dashboard")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected unauthorized user to fail")
		} else if !events.ForbiddenError.Is(e) {
			t.Errorf("Expected ForbiddenError, got: %v", e)
		}
	})

	t.Run("Path with no authorization rules requires authentication", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"}
		pathProvider := &dummyProvider{realm: "path-realm"}
		filter := security.Filter(false).
			Authentication(provider).
			Path("/secure/*").Authentication(pathProvider).Authorize().
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/secure/data")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected unauthenticated access to restricted path to fail")
		} else if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected UnauthorizedError, got: %v", e)
		}
	})

	t.Run("Path authorization with path-specific provider authenticates", func(t *testing.T) {
		rootProvider := &dummyProvider{realm: "root"}
		pathProvider := &dummyProvider{
			realm:             "path-realm",
			authenticatedUser: &security.User{Username: "pathuser", Scopes: []string{"special"}},
		}
		filter := security.Filter(false).
			Authentication(rootProvider).
			Path("/special/*").Authentication(pathProvider).Authorize(security.Scope("special")).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/special/resource")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected path authentication to succeed, got: %v", e)
		}
	})

	t.Run("Path authorization fails when path provider returns error", func(t *testing.T) {
		rootProvider := &dummyProvider{realm: "root"}
		pathProvider := &dummyProvider{
			realm:               "path-realm",
			authenticationError: events.ForbiddenError,
		}
		filter := security.Filter(false).
			Authentication(rootProvider).
			Path("/special/*").Authentication(pathProvider).Authorize(security.Scope("special")).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/special/resource")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected path authentication failure to propagate")
		}
	})

	t.Run("Authorization with All requires all to pass", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{
			Username: "admin",
			Scopes:   []string{"admin"},
			Realm:    "realm",
		}}
		filter := security.Filter(false).
			Authentication(provider).
			Path("/admin/*").Authorize(security.All(security.Scope("admin"), security.Realm("realm"))).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/admin/page")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected All authorization to pass, got: %v", e)
		}
	})

	t.Run("Authorization with Either requires one to pass", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{
			Username: "user",
			Scopes:   []string{"basic"},
			Realm:    "realm",
		}}
		filter := security.Filter(false).
			Authentication(provider).
			Path("/flexible/*").Authorize(security.Either(security.Scope("admin"), security.Realm("realm"))).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/flexible/page")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected Either authorization to pass, got: %v", e)
		}
	})
}

// TestCoverageDeferredAuthorization tests deferred authorization (AuthorizationFunc used as Authorization)
func TestCoverageDeferredAuthorization(t *testing.T) {
	t.Run("AuthorizationFunc used in path authorization", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "admin"}}
		authFunc := security.AuthorizationFunc(func(user *security.User, scope we.RequestScope) bool {
			return user != nil && user.Username == "admin"
		})
		filter := security.Filter(false).
			Authentication(provider).
			Path("/check/*").Authorize(authFunc).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/check/something")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected AuthorizationFunc to authorize admin, got: %v", e)
		}
	})

	t.Run("AuthorizationFunc denies unauthorized user", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticatedUser: &security.User{Username: "regular"}}
		authFunc := security.AuthorizationFunc(func(user *security.User, scope we.RequestScope) bool {
			return user != nil && user.Username == "admin"
		})
		filter := security.Filter(false).
			Authentication(provider).
			Path("/check/*").Authorize(authFunc).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/check/something")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected AuthorizationFunc to deny non-admin")
		} else if !events.ForbiddenError.Is(e) {
			t.Errorf("Expected ForbiddenError, got: %v", e)
		}
	})

	t.Run("AuthorizationFunc with nil user and authorization allowing nil", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"} // returns nil user
		authFunc := security.AuthorizationFunc(func(user *security.User, scope we.RequestScope) bool {
			// Authorization that allows anonymous access based on request method
			return scope.Request().Method == http.MethodGet
		})
		filter := security.Filter(false).
			Authentication(provider).
			Path("/public/*").Authorize(authFunc).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/public/page")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected authorization to pass for GET, got: %v", e)
		}
	})

	t.Run("AuthorizationFunc with nil user denying access", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"} // returns nil user
		authFunc := security.AuthorizationFunc(func(user *security.User, scope we.RequestScope) bool {
			return user != nil // requires authenticated user
		})
		filter := security.Filter(false).
			Authentication(provider).
			Path("/private/*").Authorize(authFunc).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/private/page")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected authorization to fail for unauthenticated user")
		} else if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected UnauthorizedError, got: %v", e)
		}
	})
}

// TestCoverageRegisteredEndpoints tests filter behavior with provider-owned endpoints
func TestCoverageRegisteredEndpoints(t *testing.T) {
	t.Run("Provider owned endpoint is handled by the provider", func(t *testing.T) {
		authenticated := false
		loginProvider := &dummyProviderWithEndpoints{
			realm:     "form",
			endpoints: []string{"/login"},
			authenticate: func(headers http.Header, scope we.RequestScope) (*security.User, error) {
				if scope.Request().URL.Path == "/login" {
					authenticated = true
					return &security.User{Username: "formuser"}, nil
				}
				return nil, nil
			},
		}

		filter := security.Filter(true).
			Authentication(loginProvider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost:8080/login")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if !authenticated {
			t.Error("Expected provider endpoint to be handled")
		}
	})

	t.Run("Provider owned endpoint with auth triggers", func(t *testing.T) {
		triggered := false
		loginProvider := &dummyProviderWithEndpoints{
			realm:     "form",
			endpoints: []string{"/login"},
			authenticate: func(headers http.Header, scope we.RequestScope) (*security.User, error) {
				return &security.User{Username: "formuser"}, nil
			},
		}

		trigger := func(user *security.User, scope we.RequestScope) {
			triggered = true
		}

		filter := security.Filter(true).
			Authentication(loginProvider).
			OnAuthentication(trigger).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost:8080/login")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Unexpected error: %v", e)
		}
		if !triggered {
			t.Error("Expected auth trigger to fire on endpoint authentication")
		}
	})

	t.Run("Provider owned endpoint returns error", func(t *testing.T) {
		loginProvider := &dummyProviderWithEndpoints{
			realm:     "form",
			challenge: "Basic",
			endpoints: []string{"/login"},
			authenticate: func(headers http.Header, scope we.RequestScope) (*security.User, error) {
				return nil, events.UnauthorizedError
			},
		}

		filter := security.Filter(true).
			Authentication(loginProvider).
			Build()

		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodPost, "http://localhost:8080/login")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected error from endpoint authentication")
		} else if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected UnauthorizedError, got: %v", e)
		}
		if len(headers["Www-Authenticate"]) == 0 {
			t.Error("Expected WWW-Authenticate challenge to be sent")
		}
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
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		scope.Session().Set(security.UserAttributeName, &security.User{Realm: "realm"})
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
		}
	})
	t.Run("Test invalid session authenticated call", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", valid: false}
		filter := security.Filter(security.DefaultAuthenticatedAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.Session().Set(security.UserAttributeName, &security.User{Realm: "realm"})
		if e := filter.Filter(headers, scope); e != events.UnauthorizedError {
			t.Errorf("Expected user to be unauthorized, instead got error: %v", e)
		}
	})
	t.Run("Test failed authenticated call", func(t *testing.T) {
		// Using a different weError to check if it's getting the provider error
		provider := &dummyProvider{realm: "realm", authenticationError: events.OKInterruption}
		filter := security.Filter(security.DefaultAnonymousAccess).Authentication(provider).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e != events.OKInterruption {
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
			t.Errorf("Expected user succeed in authentication, instead got error: %v", e)
		} else if scope.Get(security.UserAttributeName) != nil {
			t.Error("anonymous users should not be present in the request scope")
		} else if scope.Session().Get(security.UserAttributeName) != nil {
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
		} else if user = scope.Session().Get(security.UserAttributeName); user == nil || user.(*security.User).Username != "username" {
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
			Path("/api/*").Authentication(provider).Authorize().
			Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e != nil {
			t.Errorf("Call for unrestricted path should not fail. %v", e)
		}
	})
	t.Run("Test unauthenticated call to restricted path without challenges", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm"}
		filter := security.Filter(security.DefaultAnonymousAccess).
			Path("/*").Authentication(provider).Authorize().
			Build()
		headers := make(http.Header)
		if e := filter.Filter(headers, test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")); e == nil {
			t.Error("Unauthenticated call in restricted path should fail")
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		} else if !e.(events.WeEvent).Is(events.UnauthorizedError) {
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
		scope.Session().Set(security.UserAttributeName, &security.User{Realm: "realm"})
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected user to be authorized, instead got error: %v", e)
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
		} else if e != events.ForbiddenError {
			t.Errorf("Expected forbidden error: %v", e)
		}
	})
}

func TestFilterAnonymous(t *testing.T) {
	t.Run("Test restricted anonymous call", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticationError: events.UnauthorizedError}
		filter := security.Filter(security.DefaultAuthenticatedAccess).
			Authentication(provider).
			Path("/somewhere").Anonymous().
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to be not authorized")
		} else if e != events.UnauthorizedError {
			t.Errorf("Expected unauthorized error: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected anonymous user to be authorized: %v", e)
		}
	})
	t.Run("Test anonymous overriding", func(t *testing.T) {
		provider := &dummyProvider{realm: "realm", authenticationError: events.UnauthorizedError}
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
		} else if e != events.UnauthorizedError {
			t.Errorf("Expected unauthorized error: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected anonymous user to be authorized: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere/back")
		if e := filter.Filter(headers, scope); e == nil {
			t.Error("Expected user to be not authorized")
		} else if e != events.UnauthorizedError {
			t.Errorf("Expected unauthorized error: %v", e)
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere/else/out/back")
		if e := filter.Filter(headers, scope); e != nil {
			t.Errorf("Expected anonymous user to be authorized: %v", e)
		}
	})
}
