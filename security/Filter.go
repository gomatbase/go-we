// Copyright 2023 GOM. All rights reserved.
// Since 16/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/pathTree"
)

const (
	DefaultAnonymousAccess     = false
	DefaultAuthenticatedAccess = true
)

var UserAttributeName = "WE-SEC-USER"

type UnauthenticatedSecurityFilterBuilder interface {
	Authentication(...AuthenticationProvider) AuthenticatedSecurityFilterBuilder
	Path(paths ...string) UnauthenticatedAuthorizationBuilder
	Build() we.Filter
}

type AuthenticatedSecurityFilterBuilder interface {
	Path(paths ...string) AuthenticatedAuthorizationBuilder
	Build() we.Filter
}

type AuthenticatedAuthorizationBuilder interface {
	Authorize(...Authorization) AuthenticatedSecurityFilterBuilder
	Anonymous() AuthenticatedSecurityFilterBuilder
	Authentication(...AuthenticationProvider) AuthenticatedAuthorizationBuilder
}

type UnauthenticatedAuthorizationBuilder interface {
	Authorize(...Authorization) UnauthenticatedSecurityFilterBuilder
	Anonymous() UnauthenticatedSecurityFilterBuilder
	Authentication(...AuthenticationProvider) UnauthenticatedAuthorizationBuilder
}

type filterBuilder struct {
	authenticationProviders []AuthenticationProvider
	authorizationBuilders   []*authorizationBuilder
	restricted              bool
}

func (fb *filterBuilder) build() we.Filter {
	if len(fb.authenticationProviders) == 0 && len(fb.authorizationBuilders) == 0 {
		panic("security filter has no authentication configured")
	}

	result := &filter{
		globalProviders:         make(map[string]AuthenticationProvider),
		registeredEndpoints:     pathTree.New[authorizationRules](),
		authenticationProviders: fb.authenticationProviders,
		restricted:              fb.restricted,
	}
	for _, provider := range fb.authenticationProviders {
		if provider == nil {
			panic("nil authentication provider")
		} else if provider.Realm() == "" {
			panic("authentication provider with no realm")
		}
		if existingProvider, found := result.globalProviders[provider.Realm()]; found {
			if existingProvider != provider {
				panic("authentication provider overlapping realms")
			}
		} else {
			result.globalProviders[provider.Realm()] = provider
			for _, endpoint := range provider.Endpoints() {
				if e := result.registeredEndpoints.Add(endpoint, authorizationRules{
					authenticationProviders: []AuthenticationProvider{provider},
				}); e != nil {
					panic("Provider owned endpoint already registered")
				}
			}
		}
		if provider.Challenge() != "" {
			result.challenges = append(result.challenges, fmt.Sprintf("%s realm=\"%s\"", provider.Challenge(), provider.Realm()))
		}
	}

	if fb.authorizationBuilders != nil {
		result.authorizations = pathTree.New[authorizationRules]()
		for _, builder := range fb.authorizationBuilders {
			authorization := authorizationRules{
				authenticationProviders: builder.providers,
				authorization:           builder.authorization,
			}
			for _, provider := range builder.providers {
				if provider == nil {
					panic("nil authentication provider")
				} else if provider.Realm() == "" {
					panic("authentication provider with no realm")
				}
				if existingProvider, found := result.globalProviders[provider.Realm()]; found {
					if existingProvider != provider {
						panic("path authentication provider overloading existing realm")
					}
				} else {
					result.globalProviders[provider.Realm()] = provider
					for _, endpoint := range provider.Endpoints() {
						if e := result.registeredEndpoints.Add(endpoint, authorization); e != nil {
							panic("Provider owned endpoint already registered")
						}
					}
				}
				if provider.Challenge() != "" {
					authorization.challenges = append(authorization.challenges, fmt.Sprintf("%s realm=\"%s\"", provider.Challenge(), provider.Realm()))
				}
			}

			for _, path := range builder.paths {
				if e := result.authorizations.Add(path, authorization); e != nil {
					// either the path is invalid or it's overloading an existing path
					panic(e)
				}
			}
		}
	}

	return result
}

func (fb *filterBuilder) anonymous(paths []string) {
	if len(fb.authenticationProviders) == 0 {
		fb.authenticationProviders = []AuthenticationProvider{anonymousAuthenticationProvider(paths)}
	} else if provider, isAnonymous := fb.authenticationProviders[0].(*anonymousProvider); !isAnonymous {
		fb.authenticationProviders = append([]AuthenticationProvider{anonymousAuthenticationProvider(paths)}, fb.authenticationProviders...)
	} else {
		provider.addPaths(paths)
	}

}

type unauthenticatedSecurityFilterBuilder struct {
	builder *filterBuilder
}

func (usfb *unauthenticatedSecurityFilterBuilder) Authentication(providers ...AuthenticationProvider) AuthenticatedSecurityFilterBuilder {
	if len(providers) == 0 {
		panic("no authentication providers provided")
	}
	if len(usfb.builder.authenticationProviders) == 0 {
		usfb.builder.authenticationProviders = providers
	} else {
		usfb.builder.authenticationProviders = append(usfb.builder.authenticationProviders, providers...)
	}
	return &authenticatedSecurityFilterBuilder{builder: usfb.builder}
}

func (usfb *unauthenticatedSecurityFilterBuilder) Path(paths ...string) UnauthenticatedAuthorizationBuilder {
	return &unauthenticatedAuthorizationBuilder{unauthenticatedBuilder: usfb, authorizationBuilder: newAuthorizationBuilder(usfb.builder, paths)}
}

func (usfb *unauthenticatedSecurityFilterBuilder) Build() we.Filter {
	return usfb.builder.build()
}

type authenticatedSecurityFilterBuilder struct {
	builder *filterBuilder
}

func (asfb *authenticatedSecurityFilterBuilder) Path(paths ...string) AuthenticatedAuthorizationBuilder {
	return &authenticatedAuthorizationBuilder{authenticatedBuilder: asfb, authorizationBuilder: newAuthorizationBuilder(asfb.builder, paths)}
}

func (asfb *authenticatedSecurityFilterBuilder) Build() we.Filter {
	return asfb.builder.build()
}

type authorizationBuilder struct {
	filterBuilder *filterBuilder
	paths         []string
	authorization Authorization
	providers     []AuthenticationProvider
}

func (ab *authorizationBuilder) anonymous() {
	if len(ab.providers) != 0 {
		panic("anonymous access cannot be configured with authentication")
	}
	ab.filterBuilder.anonymous(ab.paths)
}

func (ab *authorizationBuilder) authorize(authorizations []Authorization) {
	if len(authorizations) != 0 {
		if len(authorizations) == 1 {
			ab.authorization = authorizations[0]
		} else {
			// all authorizations are required
			ab.authorization = all(authorizations)
		}
		ab.filterBuilder.authorizationBuilders = append(ab.filterBuilder.authorizationBuilders, ab)
	} else if len(ab.providers) == 0 {
		// when building a filter, a nil Authorization means that it will either rely on the path authenticators
		// or that the paths should allow anonymous access
		ab.filterBuilder.anonymous(ab.paths)
	} else {
		ab.filterBuilder.authorizationBuilders = append(ab.filterBuilder.authorizationBuilders, ab)
	}

}

func (ab *authorizationBuilder) authentication(providers []AuthenticationProvider) {
	if len(providers) == 0 {
		panic("no authentication providers provided")
	}
	ab.providers = providers
}

func newAuthorizationBuilder(fb *filterBuilder, paths []string) *authorizationBuilder {
	if len(paths) == 0 {
		panic("no paths provided")
	}
	return &authorizationBuilder{filterBuilder: fb, paths: paths}
}

type authenticatedAuthorizationBuilder struct {
	authenticatedBuilder *authenticatedSecurityFilterBuilder
	authorizationBuilder *authorizationBuilder
}

func (aab *authenticatedAuthorizationBuilder) Anonymous() AuthenticatedSecurityFilterBuilder {
	aab.authorizationBuilder.anonymous()
	return aab.authenticatedBuilder
}

func (aab *authenticatedAuthorizationBuilder) Authorize(authorizations ...Authorization) AuthenticatedSecurityFilterBuilder {
	aab.authorizationBuilder.authorize(authorizations)
	return aab.authenticatedBuilder
}

func (aab *authenticatedAuthorizationBuilder) Authentication(providers ...AuthenticationProvider) AuthenticatedAuthorizationBuilder {
	aab.authorizationBuilder.authentication(providers)
	return aab
}

type unauthenticatedAuthorizationBuilder struct {
	unauthenticatedBuilder *unauthenticatedSecurityFilterBuilder
	authorizationBuilder   *authorizationBuilder
}

func (uab *unauthenticatedAuthorizationBuilder) Anonymous() UnauthenticatedSecurityFilterBuilder {
	uab.authorizationBuilder.anonymous()
	return uab.unauthenticatedBuilder
}

func (uab *unauthenticatedAuthorizationBuilder) Authorize(authorizations ...Authorization) UnauthenticatedSecurityFilterBuilder {
	uab.authorizationBuilder.authorize(authorizations)
	return uab.unauthenticatedBuilder
}

func (uab *unauthenticatedAuthorizationBuilder) Authentication(providers ...AuthenticationProvider) UnauthenticatedAuthorizationBuilder {
	uab.authorizationBuilder.authentication(providers)
	return uab
}

func Filter(restricted bool) UnauthenticatedSecurityFilterBuilder {
	return &unauthenticatedSecurityFilterBuilder{builder: &filterBuilder{restricted: restricted}}
}

type authorizationRules struct {
	authenticationProviders []AuthenticationProvider
	authorization           Authorization
	challenges              []string
}

func (ar *authorizationRules) IsAuthorized(headers http.Header, user *User, scope we.RequestScope) (*User, error) {
	// at this stage, either there is already a user (authenticated at root level or taken from session), or
	// there is no authenticated user.

	// if there's no user yet, we try to authenticate it as a user is required for path rules.,
	if user == nil {
		var e error
		for _, provider := range ar.authenticationProviders {
			if user, e = provider.Authenticate(headers, scope); e != nil {
				return nil, e
			} else if user != nil {
				user.Realm = provider.Realm()
				break
			}
		}
		// still no user is present, it should be
		if user == nil {
			return nil, events.UnauthorizedError
		}
	}

	// A user was authenticated, if there are authorization rules...
	if ar.authorization == nil || ar.authorization.IsAuthorized(user, scope) {
		return user, nil
	}

	return user, events.ForbiddenError

}

func sendChallenges(headers http.Header, challenges []string) {
	for _, challenge := range challenges {
		headers.Add("WWW-Authenticate", challenge)
	}
}

type filter struct {
	globalProviders         map[string]AuthenticationProvider
	authenticationProviders []AuthenticationProvider
	registeredEndpoints     pathTree.Tree[authorizationRules]
	authorizations          pathTree.Tree[authorizationRules]
	challenges              []string
	restricted              bool
}

func (f *filter) Filter(header http.Header, scope we.RequestScope) error {
	var user, sessionUser *User

	// let's first check if there might be a user in session and if it's valid
	if storedUser := scope.GetFromSession(UserAttributeName); storedUser != nil {
		isUser := false
		if sessionUser, isUser = storedUser.(*User); isUser && f.globalProviders[sessionUser.Realm].IsValid(sessionUser) {
			user = sessionUser
		} else {
			// the user in session is not valid anymore, let's remove it
			scope.SetInSession(UserAttributeName, nil)
		}
	}

	if user == nil {
		// No user found
		// let's check if there is any authentication provider registered for the requested path
		if authorization, _ := f.registeredEndpoints.Get(scope.Request().URL.Path); authorization != nil {
			var e error
			if user, e = (*authorization).IsAuthorized(header, user, scope); e != nil {
				if e == events.UnauthorizedError {
					sendChallenges(header, f.challenges)
				}
				return e
			}
		}
		// let's check if the request can be authenticated at root level, in case there's still no user
		if user == nil {
			for _, provider := range f.authenticationProviders {
				if authenticatedUser, e := provider.Authenticate(header, scope); e != nil {
					return e
				} else if authenticatedUser != nil {
					if authenticatedUser == Anonymous {
						// User is authenticated as an anonymous user, meaning it's accessing resources that are public
						// it wil not be added to the request or session
						return nil
					}
					authenticatedUser.Realm = provider.Realm()
					user = authenticatedUser
					break
				}
			}
		}
	}

	// Either no credentials or an authenticated user was found, let's see if the accessed resources require authorizations
	if f.authorizations != nil {
		if authorization, _ := f.authorizations.Get(scope.Request().URL.Path); authorization != nil {
			var e error
			if user, e = (*authorization).IsAuthorized(header, user, scope); e != nil {
				if e == events.UnauthorizedError {
					sendChallenges(header, authorization.challenges)
					sendChallenges(header, f.challenges)
				}
				return e
			} else if user == nil {
				return nil
			}
		}
	}

	if user != nil {
		scope.Set(UserAttributeName, user)
		if sessionUser != user {
			scope.SetInSession(UserAttributeName, user)
		}
		return nil
	} else if !f.restricted {
		// no specific authorization rules for the given path, if it's not restricted (default is anonymous access),
		// just let it go
		return nil
	}

	sendChallenges(header, f.challenges)
	return events.UnauthorizedError
}
