// Copyright 2023 GOM. All rights reserved.
// Since 14/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

func TestBasicAuthenticationProvider(t *testing.T) {
	t.Run("Test successful user authentication", func(t *testing.T) {
		provider := security.BasicAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test:test")))
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
	t.Run("Test unsuccessful user authentication", func(t *testing.T) {
		provider := security.BasicAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test:somethingelse")))
		if user, e := provider.Authenticate(headers, scope); user != nil {
			t.Errorf("Unexpected user return when authentication should have failed: %v", *user)
		} else if e == nil {
			t.Error("Unexpected successful authentication (no error returned).")
		} else if !e.(events.WeEvent).Is(events.ForbiddenError) {
			t.Errorf("Expected Forbidden error, instead got: %s", e.Error())
		}
	})
	t.Run("Test bad credentials", func(t *testing.T) {
		provider := security.BasicAuthenticationProvider(security.User{Username: "test", Password: "test"}).Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testsomethingelse")))
		if user, e := provider.Authenticate(headers, scope); user != nil {
			t.Errorf("Unexpected user return when authentication should have failed: %v", *user)
		} else if e == nil {
			t.Error("Unexpected successful authentication (no error returned).")
		} else if !e.(events.WeEvent).Is(events.BadRequestError) {
			t.Errorf("Expected Bad Request error, instead got: %s", e.Error())
		}
		scope.SetHeader("Authorization", "Basic something")
		if user, e := provider.Authenticate(headers, scope); user != nil {
			t.Errorf("Unexpected user return when authentication should have failed: %v", *user)
		} else if e == nil {
			t.Error("Unexpected successful authentication (no error returned).")
		} else if !e.(events.WeEvent).Is(events.BadRequestError) {
			t.Errorf("Expected Bad Request error, instead got: %s", e.Error())
		}
	})
	t.Run("Test missing and ignored credentials", func(t *testing.T) {
		provider := security.BasicAuthenticationProvider().
			CredentialsProvider(security.DefaultCredentialsProvider(security.User{Username: "test", Password: "test"})).
			Build()
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		if user, e := provider.Authenticate(headers, scope); user != nil || e != nil {
			t.Error("No authorization header received, expected no user and no error")
		}

		scope.Request().Header.Set("Authorization", "Bearer something")
		if user, e := provider.Authenticate(headers, scope); user != nil || e != nil {
			t.Error("No basic authorization received, expected no user and no error")
		}

		if provider.IsValid(nil) {
			t.Error("Expected nil user to be deemed invalid")
		}

		if !provider.IsValid(&security.User{Username: "test"}) {
			t.Error("expected test user to deemed valid")
		}

		if provider.IsValid(&security.User{Username: "unknown"}) {
			t.Error("expected unknown user to deemed invalid")
		}
	})
	t.Run("Test default basic authentication", func(t *testing.T) {
		savedOutput := os.Stdout
		reader, writer, e := os.Pipe()
		if e != nil {
			panic(e)
		}
		os.Stdout = writer

		provider := security.BasicAuthenticationProvider().Build()
		// read the credentials, which are written to stdout in the form "Generated credentials: username password"
		scanner := bufio.NewScanner(reader)
		scanner.Scan()
		parts := strings.Split(scanner.Text(), " ")
		username := parts[2]
		password := parts[3]

		if realm := provider.Realm(); realm != "basic" {
			t.Errorf("Expected default \"basic\" realm. Got \"%s\" instead", realm)
		}
		if challenge := provider.Challenge(); challenge != "Basic" {
			t.Errorf("Expected \"Basic\" challenge. Got \"%s\" instead", challenge)
		}
		headers := make(http.Header)
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		scope.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
		if user, e := provider.Authenticate(headers, scope); e != nil || user == nil {
			t.Errorf("Unexpected authentication failure: user %v error %v", user, e)
		}

		if !provider.IsValid(&security.User{Username: username}) {
			t.Error("Unexpected invalid generated user")
		}

		os.Stdout = savedOutput
	})
	t.Run("Test custom realm", func(t *testing.T) {
		provider := security.BasicAuthenticationProvider(security.User{Username: "test", Password: "test"}).Realm("custom").Build()
		if realm := provider.Realm(); realm != "custom" {
			t.Errorf("Expected \"custom\" realm. Got \"%s\" instead", realm)
		}
	})
}
