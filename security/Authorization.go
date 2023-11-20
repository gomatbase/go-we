// Copyright 2023 GOM. All rights reserved.
// Since 16/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"github.com/gomatbase/go-we"
)

type Authorization interface {
	IsAuthorized(*User, we.RequestScope) bool
}

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

type Realm string

func (r Realm) IsAuthorized(user *User, _ we.RequestScope) bool {
	return user != nil && user.Realm == string(r)
}

type Origin string

func (o Origin) IsAuthorized(user *User, _ we.RequestScope) bool {
	return user != nil && user.Origin == string(o)
}
