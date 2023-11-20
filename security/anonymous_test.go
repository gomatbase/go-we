// Copyright 2023 GOM. All rights reserved.
// Since 16/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"net/http"
	"testing"

	"github.com/gomatbase/go-we/test"
)

func TestAnonymousProvider(t *testing.T) {
	t.Run("Test Faulty paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Invalid paths should raise panic")
			}
		}()
		anonymousAuthenticationProvider([]string{"invalid path"})
	})
	t.Run("Test valid paths", func(t *testing.T) {
		anonymousAuthenticationProvider([]string{"/"})
		anonymousAuthenticationProvider([]string{"/somewhere", "/elsewhere", "/somewhere"})
	})
	t.Run("Test overloading paths", func(t *testing.T) {
		provider := anonymousAuthenticationProvider([]string{"/somewhere", "/elsewhere"})
		provider.addPaths([]string{"/somewhere"})
	})
}

func TestAnonymousProvider_Authenticate(t *testing.T) {
	provider := anonymousAuthenticationProvider([]string{"/somewhere", "/somewhere/**", "/elsewhere/*/something"})
	t.Run("Test non-anonymous access", func(t *testing.T) {
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/")
		// send nil headers, as they are not expected to be used
		if user, e := provider.Authenticate(nil, scope); user != nil {
			t.Errorf("Unexpected user return for non anymous path: %v", *user)
		} else if e != nil {
			t.Error("anonymous provider should never return an error/event")
		}
	})
	t.Run("Test anonymous access", func(t *testing.T) {
		scope := test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere")
		if user, e := provider.Authenticate(nil, scope); user == nil {
			t.Error("Anonymous call should return a user")
		} else if user != Anonymous {
			t.Error("Anonymous call should return an anonymous user")
		} else if e != nil {
			t.Error("Anonymous provider should never return an error/event")
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere/")
		if user, e := provider.Authenticate(nil, scope); user == nil {
			t.Error("Anonymous call should return a user")
		} else if user != Anonymous {
			t.Error("Anonymous call should return an anonymous user")
		} else if e != nil {
			t.Error("Anonymous provider should never return an error/event")
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/elsewhere/or/something")
		if user, e := provider.Authenticate(nil, scope); user == nil {
			t.Error("Anonymous call should return a user")
		} else if user != Anonymous {
			t.Error("Anonymous call should return an anonymous user")
		} else if e != nil {
			t.Error("Anonymous provider should never return an error/event")
		}
		scope = test.MockedRequestScope(http.MethodGet, "http://localhost:8080/somewhere/something/else")
		if user, e := provider.Authenticate(nil, scope); user == nil {
			t.Error("Anonymous call should return a user")
		} else if user != Anonymous {
			t.Error("Anonymous call should return an anonymous user")
		} else if e != nil {
			t.Error("Anonymous provider should never return an error/event")
		}
	})
}

func TestAnonymousProvider_IsValid(t *testing.T) {
	provider := anonymousAuthenticationProvider([]string{"/somewhere", "/somewhere/**", "/elsewhere/*/something"})
	if !provider.IsValid(Anonymous) {
		t.Error("Anonymous users are always valid")
	}
	if !provider.IsValid(nil) {
		t.Error("No user is anonymous")
	}
	if !provider.IsValid(&User{}) {
		t.Error("Any user is always valid")
	}
}
