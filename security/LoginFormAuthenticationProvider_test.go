// Copyright 2023 GOM. All rights reserved.
// Since 15/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gomatbase/go-we/errors"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

const DefaultRenderedForm = "<!DOCTYPE html><html lang=\"en\"><head>    <meta charset=\"UTF-8\">    <title>Login</title></head><body><h2>Login</h2>%s<form action=\"/login\" method=\"post\">    <label for=\"username\">Username:</label><br>    <input type=\"text\" id=\"username\" name=\"username\"><br>    <label for=\"password\">Password:</label><br>    <input type=\"password\" id=\"password\" name=\"password\"><br><br>    <input type=\"hidden\" id=\"target\" name=\"target\" value=\"%s\"><br><br>    <input type=\"submit\" value=\"Login\"></form></body></html>"

type dummyCredentialsProvider struct{}

func (dcp *dummyCredentialsProvider) Get(username string) *security.User {
	return security.Anonymous
}

func (dcp *dummyCredentialsProvider) Authenticate(_, _ string) (*security.User, error) {
	return security.Anonymous, nil
}
func (dcp *dummyCredentialsProvider) IsValid(_ string) bool {
	return true
}

func TestCustomLoginForm(t *testing.T) {
	t.Run("Test faulty custom form", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating custom login form with invalid template should fail")
			}
		}()
		security.CustomLoginForm(security.LoginFormConfiguration{}, "{{")
	})
	t.Run("Test faulty custom form configuration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating custom login form with invalid template configuration should fail")
			}
		}()
		security.CustomLoginForm(security.LoginFormConfiguration{TargetField: "{{"}, security.DefaultTemplate)
	})
	t.Run("Test faulty error expression", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating custom login form with invalid error expression should fail")
			}
		}()
		security.CustomLoginForm(security.LoginFormConfiguration{Error: "{{"}, security.DefaultTemplate)
	})
	t.Run("Test custom form", func(t *testing.T) {
		form := security.CustomLoginForm(security.LoginFormConfiguration{Error: "something", Header: "a header"}, "{{.Header}} {{.Error}}")
		result := form.Generate("error", "target")
		if result != "a header something" {
			t.Errorf("Unexpected static form result: %s", result)
		}
		result = form.Generate("", "target")
		if result != "a header " {
			t.Errorf("Unexpected static form result: %s", result)
		}
		form = security.CustomLoginForm(security.LoginFormConfiguration{Error: "something", Header: "a header"}, "{{.Header}}")
		result = form.Generate("error", "target")
		if result != "a header" {
			t.Errorf("Unexpected static form result: %s", result)
		}
		form = security.CustomLoginForm(security.LoginFormConfiguration{Error: "{{.Error}}", Header: "a header"}, "{{.Header}} {{.Error}} {{.Target}}")
		result = form.Generate("error", "target")
		if result != "a header error target" {
			t.Errorf("Unexpected static form result: %s", result)
		}
		result = form.Generate("", "target")
		if result != "a header  target" {
			t.Errorf("Unexpected static form result: %s", result)
		}
	})
}

func TestLoginFormAuthenticationProviderBuilder(t *testing.T) {
	t.Run("Test missing credential provider", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Authentication login form provider must have a credentials provider")
			}
		}()
		security.LoginFormAuthenticationProvider().Build()
	})
	t.Run("Test faulty action url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("A faulty action should end in failure")
			}
		}()
		security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			LoginForm(security.DefaultLoginForm(security.LoginFormConfiguration{Action: ":/"})).
			Build()
	})
	t.Run("Test custom credential provider", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider().
			CredentialsProvider(&dummyCredentialsProvider{}).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("POST", "http://localhost:8080/login")
		scope.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		scope.SetBody([]byte("username=test&password=test"))
		if user, e := provider.Authenticate(headers, scope); e != nil || user != security.Anonymous {
			t.Errorf("Unexpected authentication failure and user: %v %v", user, e)
		}
		if !provider.IsValid(&security.User{Username: "test"}) {
			t.Errorf("Unexpected user not valid")
		}
		if !provider.IsValid(&security.User{Username: "test2"}) {
			t.Errorf("Unexpected user not valid")
		}
	})
}

func TestLoginFormAuthenticationProvider(t *testing.T) {
	t.Run("Test successful user authentication", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("POST", "http://localhost:8080/login")
		scope.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		scope.SetBody([]byte("username=test&password=test"))
		if user, e := provider.Authenticate(headers, scope); e != nil {
			t.Errorf("Unexpected authentication failure: %v", e)
		} else if user == nil {
			t.Error("Unexpected user not found.")
		} else if user.Username != "test" {
			t.Errorf("Unexpected user found (expected \"test\"): %s", user.Username)
		} else if len(user.Password) > 0 {
			t.Errorf("Unexpected user password present: %s", user.Password)
		}
	})
	t.Run("Test large payload login", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("POST", "http://localhost:8080/login")
		scope.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		payload := make([]byte, 1030)
		copy(payload, "username=test&password=test")
		scope.SetBody(payload)
		if _, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Expected authentication failure")
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "<h1>Error: Invalid login submission</h1>", "") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "<h1>Error: Invalid login submission</h1>", ""))
		}
	})
	t.Run("Test invalid payload login", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("POST", "http://localhost:8080/login")
		scope.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		scope.SetBody(nil)
		if _, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Expected authentication failure")
		}
	})
	t.Run("Test invalid password", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("POST", "http://localhost:8080/login")
		scope.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		scope.SetBody([]byte("username=test&password=tes&target=/somewhere"))
		if _, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Expected authentication failure")
		} else if !errors.UnauthorizedError.Is(e) {
			t.Errorf("Expected unauthorized error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "<h1>Error: invalid password</h1>", "/somewhere") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "<h1>Error: invalid password</h1>", "/somewhere"))
		}
	})
	t.Run("Test invalid user", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("POST", "http://localhost:8080/login")
		scope.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		scope.SetBody([]byte("username=tes&password=test&target=/somewhere"))
		if _, e := provider.Authenticate(headers, scope); e == nil {
			t.Error("Expected authentication failure")
		} else if !errors.UnauthorizedError.Is(e) {
			t.Errorf("Expected unauthorized error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "<h1>Error: Invalid credentials</h1>", "/somewhere") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "<h1>Error: Invalid credentials</h1>", "/somewhere"))
		}
	})
	t.Run("Test required embedded authentication", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Required(true).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/somewhere")

		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Errorf("Authentication is required, an authentication error is expected")
		} else if user != nil {
			t.Error("Unexpected user found.")
		} else if !errors.ForbiddenError.Is(e) {
			t.Errorf("Expected forbidden error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "", "/somewhere") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "", "/somewhere"))
		}
	})
	t.Run("Test required embedded non-GET authentication", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Required(true).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("PUT", "http://localhost:8080/somewhere")

		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Errorf("Authentication is required, an authentication error is expected")
		} else if user != nil {
			t.Error("Unexpected user found.")
		} else if !errors.ForbiddenError.Is(e) {
			t.Errorf("Expected forbidden error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "", "/") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "", "/"))
		}
	})
	t.Run("Test required redirected authentication", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Required(true).RedirectToForm(true).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("GET", "http://localhost:8080/somewhere")

		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Errorf("Authentication is required, an authentication error is expected")
		} else if user != nil {
			t.Error("Unexpected user found.")
		} else if !errors.FoundRedirect.Is(e) {
			t.Errorf("Expected forbidden error, got %v", e)
		} else if headers.Get("Location") != "http://localhost:8080/login?target=%2Fsomewhere" {
			t.Errorf("Expected redirection to login form with target page, instead got: %s", headers.Get("Location"))
		}
	})
	t.Run("Test required redirected non-GET authentication", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Required(true).RedirectToForm(true).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("PUT", "http://localhost:8080/somewhere")

		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Errorf("Authentication is required, an authentication error is expected")
		} else if user != nil {
			t.Error("Unexpected user found.")
		} else if !errors.FoundRedirect.Is(e) {
			t.Errorf("Expected forbidden error, got %v", e)
		} else if headers.Get("Location") != "http://localhost:8080/login" {
			t.Errorf("Expected redirection to login form without target page, instead got: %s", headers.Get("Location"))
		}
	})
	t.Run("Test get login form", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Required(true).RedirectToForm(true).Build()
		headers := make(http.Header)

		scope := test.MockedRequestScope("GET", "http://localhost:8080/login?target=/somewhere")
		if user, e := provider.Authenticate(headers, scope); e == nil {
			t.Errorf("Login form is getting requested, an interruption is expected")
		} else if user != nil {
			t.Error("Unexpected user found.")
		} else if !errors.OKInterruption.Is(e) {
			t.Errorf("Expected an OK interruption error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "", "/somewhere") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "", "/somewhere"))
		}

		scope = test.MockedRequestScope("GET", "http://localhost:8080/login")
		if _, e := provider.Authenticate(headers, scope); !errors.OKInterruption.Is(e) {
			t.Errorf("Expected an OK interruption error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "", "/") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "", "/"))
		}
		provider = security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Required(true).RedirectToForm(true).DefaultAuthenticatedRedirectionPath("/api").Build()
		if _, e := provider.Authenticate(headers, scope); !errors.OKInterruption.Is(e) {
			t.Errorf("Expected an OK interruption error, got %v", e)
		} else if e.(errors.WeError).Payload().Content != fmt.Sprintf(DefaultRenderedForm, "", "/api") {
			t.Errorf("Unexpected rendered form: \n%s\n%s", e.(errors.WeError).Payload().Content, fmt.Sprintf(DefaultRenderedForm, "", "/api"))
		}
	})
	t.Run("Test non-required authentication", func(t *testing.T) {
		provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope("PUT", "http://localhost:8080/somewhere")

		if user, e := provider.Authenticate(headers, scope); e != nil {
			t.Errorf("non-required authentication should not fail for requests without credentials")
		} else if user != nil {
			t.Error("Unexpected user found.")
		}
	})
}

func TestLoginFormAuthenticationProvider_Realm(t *testing.T) {
	provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
		Realm("something").Build()
	if provider.Realm() != "something" {
		t.Errorf("Unexpected realm: %s", provider.Realm())
	}
}

func TestLoginFormAuthenticationProvider_IsValid(t *testing.T) {
	provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
		Build()
	if provider.IsValid(nil) {
		t.Errorf("nil users are never valid")
	}
	if !provider.IsValid(&security.User{Username: "test"}) {
		t.Errorf("user is valid if it exists")
	}
	if provider.IsValid(&security.User{Username: "test1"}) {
		t.Errorf("user is not valid if it doesn't exist")
	}
}

func TestLoginFormAuthenticationProvider_Challenge(t *testing.T) {
	// prepare test to allow challenge configuration
	provider := security.LoginFormAuthenticationProvider(security.User{Username: "test", Password: "test"}).
		Build()
	if provider.Challenge() != "" {
		t.Errorf("Unexpected challenge: %s", provider.Challenge())
	}
}
