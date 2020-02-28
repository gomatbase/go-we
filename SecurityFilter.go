// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"log"
	"net/http"
	"net/url"
)


const (
	DEFAULT_SESSION_COOKIE_NAME = "WE-SESSION-ID"

	IGNORE_PATH_PEG = ""
)

var (
	uaaClient string
	appLoginEndpoint string
)


var (
	sessionTimeout float64
)

/**
The Security Filter is a default authentication/authorization checker that can be added as a filter to process incoming
http requests.

This filter will, by default, process every incoming http requests. Ignore expressions can be added to the filter which
will allow the Security Filter to overlook checks for any of the incoming endpoints matching the path expression

If the endpoint is for an authorization dependent endpoint (so, a non-ignorable endpoint), it will check if a session exists
for the incoming request, and if not, it will trigger the configured authorization provider(s) if the request is authorized,
and if not it will use the authorization provider to get instructions of how to react to the incoming request.

By default, the security filter is created with an anonymous authentication provider, which accepts all requests, and will
allow the security filter to create sessions if sessions are active.

By default it will have an Anonymous authentication provider which will basically initiate a session with a placeholder
map for session scoped objects
 */
type SecurityFilter struct {
	// Path Match tree to check for ignore paths
	ignoreMap              *pathTree
	authenticationUrl      url.URL
	authenticationProvider *AuthenticationProvider

	// attributes to handle sessions
	// if sessions are to be created for incoming requests
	useSessions bool
	// map of active sessions
	sessions map[string]*Session
	// if sessions are identified with cookies
	useSessionCookies bool
	// the cookie name used to hold the session id
	sessionCookieName     string
}

// Create and initialize a new security filter
func NewSecurityFilter() *SecurityFilter {
	result := new(SecurityFilter)
	result.ignoreMap = newPathTree()
	result.sessions = make(map[string]*Session)
	result.sessionCookieName = DEFAULT_SESSION_COOKIE_NAME
	return result
}

func (sf *SecurityFilter) Ignore(path string) {
	sf.ignoreMap.addHandler(path, IGNORE_PATH_PEG)
}

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

func (sf *SecurityFilter) Filter(w http.ResponseWriter, ctx *RequestContext) (bool, error) {
	if peg, _ := sf.ignoreMap.getHandlerAndPathVariables(ctx.Request.URL.Path); peg == nil {
		log.Println("Security being checked")
		if (*sf.authenticationProvider).IsAuthorized(ctx) {
			// the authorization provider considers the request authorized.
			return true, nil
		}

		// not authorized, let's handle the authorization
		if !(*sf.authenticationProvider).HandleAuthentication(w, ctx) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		return false, nil
	}

	return true, nil
}

