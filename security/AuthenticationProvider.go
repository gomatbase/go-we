// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package security

import (
	"net/http"

	"github.com/gomatbase/go-we"
)

const (
	OAUTH2_PROVIDER = iota
	BASIC_AUTH_PROVIDER
	BEARER_AUTH_PROVIDER
	LOGIN_FORM_PROVIDER
)

type AuthenticationProvider interface {
	GetType() uint32
	IsAuthorized(scope we.RequestScope) bool
	HandleAuthentication(headers http.Header, scope we.RequestScope) bool
}

type OAuth2AuthenticationProvider interface {
	AuthenticationProvider
	AuthorizationCodeCallbackEndpoint() string
}

type LoginFormAuthenticationProvider interface {
	AuthenticationProvider
	LoginFormEndpoint() string
}
