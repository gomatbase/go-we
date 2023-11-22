// Copyright 2023 GOM. All rights reserved.
// Since 16/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/pathTree"
)

const peg = true

// Anonymous is a special user that is used to represent anonymous users. An authentication provider implementation may
// return the Anonymous user to indicate that the request is authenticated/allowed, but the user is not known. The
// authorization may still deny access to anonymous users.
var Anonymous = &User{}

// anonymousAuthenticationProvider initializes an anonymousProvider authentication provider
func anonymousAuthenticationProvider(paths []string) *anonymousProvider {
	provider := &anonymousProvider{
		paths: pathTree.New[bool](),
	}

	provider.addPaths(paths)

	return provider
}

// anonymousProvider is the internal authentication provider used to identify anonymously accessible paths.
// It's meant to be used by the security filter, always at the root level and always the first authentication provider
// so it takes precedence to any other authentication/authorization means.
type anonymousProvider struct {
	paths pathTree.Tree[bool]
}

// addPaths will add the given paths to the existing list of paths for anonymous authorization
func (ap *anonymousProvider) addPaths(paths []string) {
	for _, path := range paths {
		// for existing paths it doesn't matter, as it is meant just as ap match. Invalid paths raises panic
		if e := ap.paths.Add(path, peg); e != nil && e != pathTree.ExistingPathError {
			panic(e)
		}
	}
}

// Authenticate implements the AuthenticationProvider interface and will return the Anonymous user for any
// request for one of the configured anonymous path expressions
func (ap *anonymousProvider) Authenticate(_ http.Header, scope we.RequestScope) (*User, error) {
	if peg, _ := ap.paths.Get(scope.Request().URL.Path); peg != nil {
		return Anonymous, nil
	}
	return nil, nil
}

// Realm implements the AuthenticationProvider interface and will return the realm "anonymous"
func (ap *anonymousProvider) Realm() string {
	return "anonymous"
}

// IsValid implements the AuthenticationProvider interface and will always return true
func (ap *anonymousProvider) IsValid(user *User) bool {
	// any user is valid
	return true
}

// Challenge implements the AuthenticationProvider interface and returns no challenge
func (ap *anonymousProvider) Challenge() string {
	return ""
}
