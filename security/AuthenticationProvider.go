// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package security

import (
	"net/http"

	"github.com/gomatbase/go-we"
)

// AuthenticationProvider is an interface for authentication provider implementations. Authentication providers can
// be addedto a security filter to provider users that will be added to the reqeust scope.
type AuthenticationProvider interface {
	// Authenticate Tries to authenticate the incoming request. Each provider should extract from the incoming request
	// the information required to authenticate it. If none of the required attributes are present in the request, then the
	// provider should return a nil user and no error. If the request does have authentication credentials, and they
	// cannot be validated, then it should return an error. Successful authentication returns a user object and no error.
	Authenticate(headers http.Header, scope we.RequestScope) (*User, error)
	// Realm returns the provider authentication realm. Each provider should authenticate users for a distinct realm
	// within the same application. This realm is used to identify the authentication provider when checking if the user
	// is still value
	Realm() string
	// IsValid checks if the provided user is still authenticated
	IsValid(user *User) bool
	// Challenge returns the authentication challenge to be sent to the client with WWW-Authenticate header. It should not
	// contain the realm, which is added by the filter. An empty challenge means that the provider does not produce
	// WWW-Authenticate response headers
	Challenge() string
}
