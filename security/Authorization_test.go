// Copyright 2023 GOM. All rights reserved.
// Since 19/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"testing"

	"github.com/gomatbase/go-we/security"
)

func TestOrigin(t *testing.T) {
	authorization := security.Origin("some origin")
	user := &security.User{Origin: "origin"}
	if authorization.IsAuthorized(user, nil) {
		t.Error("User from a different origin should not be authorized")
	}
	user.Origin = "some origin"
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User from the expected origin should be authorized")
	}
	if authorization.IsAuthorized(nil, nil) {
		t.Error("Nil user should not be authorized")
	}
	if authorization.IsAuthorized(security.Anonymous, nil) {
		t.Error("Anonymous user should not be authorized")
	}
}

func TestRealm(t *testing.T) {
	authorization := security.Realm("some realm")
	user := &security.User{Realm: "realm"}
	if authorization.IsAuthorized(user, nil) {
		t.Error("User from a different realm should not be authorized")
	}
	user.Realm = "some realm"
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User from the expected realm should be authorized")
	}
	if authorization.IsAuthorized(nil, nil) {
		t.Error("Nil user should not be authorized")
	}
	if authorization.IsAuthorized(security.Anonymous, nil) {
		t.Error("Anonymous user should not be authorized")
	}
}

func TestScope(t *testing.T) {
	authorization := security.Scope("some scope")
	user := &security.User{Scopes: []string{"scope"}}
	if authorization.IsAuthorized(user, nil) {
		t.Error("User without the expected scope should not be authorized")
	}
	user.Scopes = append(user.Scopes, "some scope")
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User with the expected scope should be authorized")
	}
	user.Scopes = append(user.Scopes, "some other scope")
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User with the expected scope should be authorized")
	}
	if authorization.IsAuthorized(nil, nil) {
		t.Error("Nil user should not be authorized")
	}
	if authorization.IsAuthorized(security.Anonymous, nil) {
		t.Error("Anonymous user should not be authorized")
	}
}

func TestEither(t *testing.T) {
	authorization := security.Either(security.Scope("some scope"), security.Realm("some realm"))
	user := &security.User{Scopes: []string{"scope"}}
	if authorization.IsAuthorized(user, nil) {
		t.Error("User without the expected scope should not be authorized")
	}
	user.Scopes = append(user.Scopes, "some scope")
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User with the expected scope should be authorized")
	}
	user.Scopes = []string{"scope"}
	user.Realm = "some realm"
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User with the expected realm should be authorized")
	}
	user.Realm = "some other realm"
	if authorization.IsAuthorized(user, nil) {
		t.Error("User without the expected realm should not be authorized")
	}
	if authorization.IsAuthorized(nil, nil) {
		t.Error("Nil user should not be authorized")
	}
	if authorization.IsAuthorized(security.Anonymous, nil) {
		t.Error("Anonymous user should not be authorized")
	}
}

func TestAll(t *testing.T) {
	authorization := security.All(security.Scope("some scope"), security.Realm("some realm"))
	user := &security.User{Scopes: []string{"scope"}}
	if authorization.IsAuthorized(user, nil) {
		t.Error("User without the expected scope should not be authorized")
	}
	user.Scopes = append(user.Scopes, "some scope")
	if authorization.IsAuthorized(user, nil) {
		t.Error("User without the expected realm should not be authorized")
	}
	user.Realm = "some realm"
	if !authorization.IsAuthorized(user, nil) {
		t.Error("User with both the expected realm and scope should be authorized")
	}
	user.Scopes = []string{"scope"}
	if authorization.IsAuthorized(user, nil) {
		t.Error("User without the expected scope should not be authorized")
	}

	if authorization.IsAuthorized(nil, nil) {
		t.Error("Nil user should not be authorized")
	}
	if authorization.IsAuthorized(security.Anonymous, nil) {
		t.Error("Anonymous user should not be authorized")
	}
}
