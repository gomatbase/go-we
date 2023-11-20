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

var Anonymous = &User{}

func anonymousAuthenticationProvider(paths []string) *anonymousProvider {
	provider := &anonymousProvider{
		paths: pathTree.New[bool](),
	}

	provider.addPaths(paths)

	return provider
}

type anonymousProvider struct {
	paths pathTree.Tree[bool]
}

func (ap *anonymousProvider) addPaths(paths []string) {
	for _, path := range paths {
		// for existing paths it doesn't matter, as it is meant just as ap match. Invalid paths raises panic
		if e := ap.paths.Add(path, peg); e != nil && e != pathTree.ExistingPathError {
			panic(e)
		}
	}
}

func (ap *anonymousProvider) Authenticate(_ http.Header, scope we.RequestScope) (*User, error) {
	if peg, _ := ap.paths.Get(scope.Request().URL.Path); peg != nil {
		return Anonymous, nil
	}
	return nil, nil
}

func (ap *anonymousProvider) Realm() string {
	return "anonymous"
}

func (ap *anonymousProvider) IsValid(user *User) bool {
	// any user is valid
	return true
}

func (ap *anonymousProvider) Challenge() string {
	return ""
}
