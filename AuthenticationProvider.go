// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"net/http"
)

const (
	OAUTH2_PROVIDER = iota
	BASIC_AUTH_PROVIDER
	BEARER_AUTH_PROVIDER
	LOGIN_FORM_PROVIDER
)

type AuthenticationProvider interface {
	GetType() uint32
	IsAuthorized(scope RequestScope) bool
	HandleAuthentication(w http.ResponseWriter, scope RequestScope) bool
}

type OAuth2AuthenticationProvider interface {
	AuthenticationProvider
	AuthorizationCodeCallbackEndpoint() string
}

type LoginFormAuthenticationProvider interface {
	AuthenticationProvider
	LoginFormEndpoint() string
}
