// Copyright 2023 GOM. All rights reserved.
// Since 22/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"encoding/base64"
	"testing"

	"github.com/gomatbase/go-we/errors"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

type dummyIntrospector struct {
	user *security.User
	e    error
}

func (di *dummyIntrospector) Introspect(_ string) (*security.User, error) {
	return di.user, di.e
}

func TestBearerAuthenticationProviderBuilder(t *testing.T) {
	t.Run("Test Realm", func(t *testing.T) {
		provider := security.BearerAuthenticationProvider().Realm("Test Realm").Introspector(&dummyIntrospector{}).Build()
		if provider.Realm() != "Test Realm" {
			t.Error("Realm not set correctly.")
		}
		provider = security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{}).Build()
		if provider.Realm() != "Bearer" {
			t.Error("Default realm should be bearer")
		}
	})

	t.Run("Test Challenge", func(t *testing.T) {
		provider := security.BearerAuthenticationProvider().Challenge("Test Challenge").Introspector(&dummyIntrospector{}).Build()
		if provider.Challenge() != "Test Challenge" {
			t.Error("Challenge not set correctly.")
		}
		provider = security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{}).Build()
		if provider.Challenge() != "" {
			t.Error("Default challenge should be empty")
		}
	})

	t.Run("Test Introspector", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("BearerAuthenticationProvider should panic when no token introspector is given.")
			}
		}()
		security.BearerAuthenticationProvider().Build()
	})
}

func TestBearerAuthenticationProvider_IsValid(t *testing.T) {
	provider := security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{}).Build()
	if provider.IsValid(nil) {
		t.Error("nil users should always be invalid")
	}
	if provider.IsValid(&security.User{}) {
		t.Error("provider should not support sessions by default")
	}
	provider = security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{}).SessionsSupported(false).Build()
	if provider.IsValid(nil) {
		t.Error("nil users should always be invalid")
	}
	if provider.IsValid(&security.User{}) {
		t.Error("users are never valid when sessions are not supported")
	}
	provider = security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{}).SessionsSupported(true).Build()
	if provider.IsValid(nil) {
		t.Error("nil users should always be invalid")
	}
	if !provider.IsValid(&security.User{}) {
		t.Error("all users are valid when sessions are supported")
	}
}

func TestBearerAuthenticationProvider_Authenticate(t *testing.T) {
	t.Run("Test Authenticate with no given credentials", func(t *testing.T) {
		provider := security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{user: &security.User{}}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080/test")
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Errorf("unauthenticated request should not return an error: %v", e)
		} else if user != nil {
			t.Errorf("unauthenticated request should not return a user: %v", user)
		}
	})
	t.Run("Test Authenticate with no bearer authorization", func(t *testing.T) {
		provider := security.BearerAuthenticationProvider().Introspector(&dummyIntrospector{user: &security.User{}}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080/test")
		scope.SetHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test:test")))
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Errorf("non bearer authorization request should not return an error: %v", e)
		} else if user != nil {
			t.Errorf("non bearer authorization request should not return a user: %v", user)
		}
	})
	t.Run("Test successful authentication", func(t *testing.T) {
		introspector := &dummyIntrospector{user: &security.User{}}
		provider := security.BearerAuthenticationProvider().Introspector(introspector).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080/test")
		scope.SetHeader("Authorization", "Bearer something")
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Errorf("Authenticated request should not return an error: %v", e)
		} else if user != introspector.user {
			t.Errorf("unexpected user returned: %v", user)
		}
	})
	t.Run("Test unsuccessful authentication", func(t *testing.T) {
		introspector := &dummyIntrospector{user: &security.User{}, e: errors.New(500, "something")}
		provider := security.BearerAuthenticationProvider().Introspector(introspector).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080/test")
		scope.SetHeader("Authorization", "Bearer something")
		if user, e := provider.Authenticate(nil, scope); !errors.UnauthorizedError.Is(e) {
			t.Errorf("Authentication failure should return UnauthorizedError: %v", e)
		} else if user != nil {
			t.Errorf("Authentication failure should not return a user: %v", user)
		}
	})
}
