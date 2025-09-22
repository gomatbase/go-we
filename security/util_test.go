// Copyright 2024 GOM. All rights reserved.
// Since 30/01/2024 By GOM
// Licensed under MIT License

package security_test

import (
	"testing"

	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

func TestGetUser(t *testing.T) {
	scope := test.MockedRequestScope("GET", "http://localhost/")

	user := security.GetUser(scope)
	if user != nil {
		t.Error("Expected nil user")
	}

	scope.SetInSession(security.UserAttributeName, new(any))
	user = security.GetUser(scope)
	if user != nil {
		t.Error("Expected nil user")
	}

	sessionUser := &security.User{Username: "username"}
	scope.SetInSession(security.UserAttributeName, sessionUser)
	user = security.GetUser(scope)
	if user == nil {
		t.Error("Expected user in session")
	} else if user != sessionUser {
		t.Errorf("Expected user in session to be %v, got %v", sessionUser, user)
	}
}
