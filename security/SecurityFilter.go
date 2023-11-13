// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package security

import (
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/errors"
)

// Security Filter constants
const (
	// The security filter uses a PathTree to manage authenticated endpoints. This "peg" is used as a handler for
	// the path tree, identifying an endpoint that should be authenticated
	IGNORE_PATH_PEG = ""
)

// The Security Filter is a default authentication/authorization checker that can be added as a filter to process incoming
// http requests.
//
// This filter will, by default, process every incoming http requests. Ignore expressions can be added to the filter which
// will allow the Security Filter to overlook checks for any of the incoming endpoints matching the path expression (which
// by default will be for all)
//
// If the endpoint is for an authorization dependent endpoint (so, a non-ignorable endpoint), it will check if a session exists
// for the incoming request, and if not, it will trigger the configured authorization provider(s) if the request is authorized,
// and if not it will use the authorization provider to get instructions of how to react to the incoming request depending of
// the type of the configured authentication provider (supporting three basic use cases, Basic Authentication, Login Form and
// oauth2).
//
// By default, the security filter is created with an anonymous authentication provider, which accepts all requests.
type SecurityFilter struct {
	// Path Match tree to check for ignore paths
	ignoreMap *we.PathTree

	// The authentication provider used to verify and trigger authentication
	authenticationProvider *AuthenticationProvider
}

// Create and initialize a new security filter
func NewSecurityFilter() *SecurityFilter {
	result := new(SecurityFilter)
	result.ignoreMap = we.NewPathTree()
	return result
}

// Adds a path to the ignore list
func (sf *SecurityFilter) Ignore(path string) {
	sf.ignoreMap.AddHandler(path, IGNORE_PATH_PEG)
}

// Sets the authentication provider that should be used to handle authentication life-cycle
func (sf *SecurityFilter) SetAuthenticationProvider(provider AuthenticationProvider) {
	sf.authenticationProvider = &provider

	switch provider.GetType() {
	case OAUTH2_PROVIDER:
		callbackEndpoint := provider.(OAuth2AuthenticationProvider).AuthorizationCodeCallbackEndpoint()
		sf.Ignore(callbackEndpoint)
	case LOGIN_FORM_PROVIDER:
		callbackEndpoint := provider.(LoginFormAuthenticationProvider).LoginFormEndpoint()
		sf.Ignore(callbackEndpoint)
	}
}

// Web Engine Filter implementation that will check if incoming requests are accessing authenticated endpoints, and if
// so that they are properly authenticated. Depending on the type of authenticated provider, it may result in a
// redirection response to an authentication url (for login form authentication providers as well as some flavours of
// oauth2)
func (sf *SecurityFilter) Filter(headers http.Header, scope we.RequestScope) error {
	if peg, _ := sf.ignoreMap.GetHandlerAndPathVariables(scope.Request().URL.Path); peg == nil {
		if (*sf.authenticationProvider).IsAuthorized(scope) {
			// the authorization provider considers the request authorized.
			return nil
		}

		// not authorized, let's handle the authorization
		if !(*sf.authenticationProvider).HandleAuthentication(headers, scope) {
			return errors.UnauthorizedError
		}
	}

	return nil
}
