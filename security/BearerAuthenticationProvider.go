// Copyright 2023 GOM. All rights reserved.
// Since 22/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"net/http"
	"strings"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

const BearerRealm = "Bearer"

// TokenIntrospector allows introspecting a bearer token and return a user for it.
// If there are no means to translate the token to a user, an error must be returned.
type TokenIntrospector interface {
	Introspect(token string) (*User, error)
}

func BearerAuthenticationProvider() BearerAuthenticationProviderBuilder {
	return &bearerAuthenticationProviderBuilder{provider: &bearerAuthenticationProvider{}}
}

type BearerAuthenticationProviderBuilder interface {
	Realm(string) BearerAuthenticationProviderBuilder
	Challenge(string) BearerAuthenticationProviderBuilder
	SessionsSupported(bool) BearerAuthenticationProviderBuilder
	Introspector(TokenIntrospector) BearerAuthenticationProviderBuilder
	Build() AuthenticationProvider
}

type bearerAuthenticationProviderBuilder struct {
	provider *bearerAuthenticationProvider
}

func (bapb *bearerAuthenticationProviderBuilder) Realm(realm string) BearerAuthenticationProviderBuilder {
	bapb.provider.realm = realm
	return bapb
}

func (bapb *bearerAuthenticationProviderBuilder) Challenge(challenge string) BearerAuthenticationProviderBuilder {
	bapb.provider.challenge = challenge
	return bapb
}

func (bapb *bearerAuthenticationProviderBuilder) SessionsSupported(supportSessions bool) BearerAuthenticationProviderBuilder {
	bapb.provider.supportSessions = supportSessions
	return bapb
}

func (bapb *bearerAuthenticationProviderBuilder) Introspector(tokenIntrospector TokenIntrospector) BearerAuthenticationProviderBuilder {
	bapb.provider.tokenIntrospector = tokenIntrospector
	return bapb
}

func (bapb *bearerAuthenticationProviderBuilder) Build() AuthenticationProvider {
	if len(bapb.provider.realm) == 0 {
		bapb.provider.realm = BearerRealm
	}
	if bapb.provider.tokenIntrospector == nil {
		panic("identity provider is required")
	}
	return bapb.provider
}

type bearerAuthenticationProvider struct {
	realm             string
	tokenIntrospector TokenIntrospector
	challenge         string
	supportSessions   bool
}

func (bap *bearerAuthenticationProvider) Authenticate(_ http.Header, scope we.RequestScope) (*User, error) {
	if authorization := scope.Request().Header.Get("Authorization"); len(authorization) > 7 &&
		strings.HasPrefix(strings.ToLower(authorization[:7]), "bearer ") {

		token := authorization[7:]
		if user, e := bap.tokenIntrospector.Introspect(token); e != nil || user == nil {
			return nil, events.UnauthorizedError
		} else {
			return user, nil
		}
	}
	return nil, nil
}

func (bap *bearerAuthenticationProvider) Realm() string {
	return bap.realm
}

func (bap *bearerAuthenticationProvider) IsValid(user *User) bool {
	// if the bearer provider supports sessions, then isValid should return true for any user, as
	// it trusts that the security filter will only check users that were created from this provider and that
	// the validity of the session is managed by the session manager. If not, then we should always force the
	// token to be used, meaning... not valid and authorization must be checked. Nil users should never be considered
	// valid
	return user != nil && bap.supportSessions
}

func (bap *bearerAuthenticationProvider) Challenge() string {
	return bap.challenge
}

func (bap *bearerAuthenticationProvider) Endpoints() []string {
	return nil
}
