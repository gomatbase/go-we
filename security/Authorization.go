// Copyright 2023-2026 GOM. All rights reserved.
// Since 16/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"github.com/gomatbase/go-we"
)

type AuthorizationFunc func(*User, we.RequestScope) bool

func (f AuthorizationFunc) IsAuthorized(user *User, scope we.RequestScope) bool {
	return f(user, scope)
}

type Authorization interface {
	IsAuthorized(*User, we.RequestScope) bool
}

// All returns an Authorization that requires all provided authorizations to pass.
// The authorizations are evaluated in order and fail fast (returns false on first failure).
//
// Example:
//
//	auth := security.All(
//	    security.Scope("admin"),
//	    security.AuthorizationFunc(func(u *User, s we.RequestScope) bool {
//	        return u.Username == "superadmin"
//	    }),
//	)
func All(authorizations ...Authorization) Authorization {
	return all(authorizations)
}

type all []Authorization

func (a all) IsAuthorized(user *User, scope we.RequestScope) bool {
	for _, authorization := range a {
		if !authorization.IsAuthorized(user, scope) {
			return false
		}
	}
	return true
}

// Either returns an Authorization that requires at least one of the provided authorizations to pass.
// The authorizations are evaluated in order and short-circuit (returns true on first success).
//
// Example:
//
//	auth := security.Either(
//	    security.Scope("admin"),
//	    security.Scope("moderator"),
//	)
func Either(authorizations ...Authorization) Authorization {
	return either(authorizations)
}

type either []Authorization

func (e either) IsAuthorized(user *User, scope we.RequestScope) bool {
	for _, authorization := range e {
		if authorization.IsAuthorized(user, scope) {
			return true
		}
	}
	return false
}

type Scope string

func (s Scope) IsAuthorized(user *User, _ we.RequestScope) bool {
	if user == nil {
		return false
	}

	for _, scope := range user.Scopes {
		if scope == string(s) {
			return true
		}
	}
	return false
}

type Method string

func (s Method) IsAuthorized(_ *User, r we.RequestScope) bool {
	return r.Request().Method == string(s)
}

type Realm string

func (r Realm) IsAuthorized(user *User, _ we.RequestScope) bool {
	return user != nil && user.Realm == string(r)
}

type Origin string

func (o Origin) IsAuthorized(user *User, _ we.RequestScope) bool {
	return user != nil && user.Origin == string(o)
}

type Authorized bool

func (a Authorized) IsAuthorized(user *User, _ we.RequestScope) bool { return bool(a) }
