// Copyright 2024-2026 GOM. All rights reserved.
// Since 30/01/2024 By GOM
// Licensed under MIT License

package security

import "github.com/gomatbase/go-we"

// GetUser retrieves the authenticated User from the request scope.
// Returns nil if no user is authenticated or if the security filter is not enabled.
//
// Example:
//
//	func handler(w http.ResponseWriter, scope we.RequestScope) error {
//	    user := security.GetUser(scope)
//	    if user == nil {
//	        return events.UnauthorizedError
//	    }
//	    w.Write([]byte("Hello, " + user.Username))
//	    return nil
//	}
func GetUser(scope we.RequestScope) *User {
	if user, isType := scope.Get(UserAttributeName).(*User); isType {
		return user
	}
	return nil
}
