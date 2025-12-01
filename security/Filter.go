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

// UserAttributeName is the name under which the authenticated user is stored in the request scope
var UserAttributeName = "WE-SEC-USER"

// FilterBuilder is a security filter builder for handy chain configurations.
type FilterBuilder interface {
	// Authentication will add root level authentication providers. It can be cumulatively called and will add
	// authentication providers to the existing list
	Authentication(...AuthenticationProvider) FilterBuilder
	// Path will initiate a builder to configure path based security rules applying to all provided paths.
	Path(paths ...string) PathSecurityRulesBuilder
	// OnAuthentication will add triggers to be executed when a user is authenticated . The triggers will be executed
	// in the order they are added.
	OnAuthentication(triggers ...func(*User, we.RequestScope)) FilterBuilder
	// Build validates and builds the security filter
	Build() we.Filter
}

// PathSecurityRulesBuilder configures path based security rules for a security filter
type PathSecurityRulesBuilder interface {
	// Authorize will configure any authorization rules that should apply to the paths being configured.
	Authorize(...Authorization) FilterBuilder
	// Anonymous specifies that the paths being configured allow anonymous access. Raises a panic if authentication
	// is already configured for the paths
	Anonymous() FilterBuilder
	// Authentication will add specific authentication providers that can also be used to identify a user accessing the
	// paths. Raises a panic if anonymous access has already been configured for the paths. The resulting builder will
	// resume the root level configuration for a root-level authenticated filter.
	Authentication(...AuthenticationProvider) PathSecurityRulesBuilder
}

// filterBuilder is the internal security filter builder implementation.
type filterBuilder struct {
	// list of configured authentication providers
	authenticationProviders []AuthenticationProvider
	// list of authorization builders containing the configured authorization rules
	authorizationBuilders []*pathSecurityRuleBuilder
	// list of onAuthentication triggers
	authenticationTriggers []func(*User, we.RequestScope)
	// if the built security filter should have restricted (non-anonymous) access by default (for any path which is
	// not specifically configured)
	restricted bool
}

// Authentication adds the configured authentiction providers and converts the builder to an authenticated security filter builder.
func (fb *filterBuilder) Authentication(providers ...AuthenticationProvider) FilterBuilder {
	if len(providers) == 0 {
		panic("no authentication providers provided")
	}

	if len(fb.authenticationProviders) == 0 {
		fb.authenticationProviders = providers
	} else {
		fb.authenticationProviders = append(fb.authenticationProviders, providers...)
	}
	return fb
}

// Path returns a builder for path based security rules applicable to the given list of paths.
func (fb *filterBuilder) Path(paths ...string) PathSecurityRulesBuilder {
	if len(paths) == 0 {
		panic("a list of paths must be provided")
	}
	return &pathSecurityRuleBuilder{
		filterBuilder: fb,
		paths:         paths,
	}
}

// OnAuthentication adds triggers to be executed when a user is authenticated by a root level authentication provider.
func (fb *filterBuilder) OnAuthentication(triggers ...func(user *User, scope we.RequestScope)) FilterBuilder {
	if len(triggers) == 0 {
		panic("no triggers provided")
	}
	fb.authenticationTriggers = append(fb.authenticationTriggers, triggers...)
	return fb
}

// Build validates and builds the security filter according to the provided configuration. A non-valid configuration
// results in a panic as it should be considered a system/use error.
func (fb *filterBuilder) Build() we.Filter {

	// If there is no authentication mechanism in place and no authorization rules, the filter is useless
	if len(fb.authenticationProviders) == 0 && len(fb.authorizationBuilders) == 0 {
		panic("security filter has no authentication or authorization configured")
	}

	result := &filter{
		globalProviders:         make(map[string]AuthenticationProvider),
		registeredEndpoints:     pathTree.New[authorizationRules](),
		authenticationProviders: fb.authenticationProviders,
		restricted:              fb.restricted,
	}

	// validate all configured authentication providers before adding them to the filter
	for _, provider := range fb.authenticationProviders {
		// panic if a nil provider has been added or if a provider is added with no realm (realms are mandatory)
		if provider == nil {
			panic("nil authentication provider")
		} else if provider.Realm() == "" {
			panic("authentication provider with no realm")
		}
		// all authentication providers must serve a unique realm
		if existingProvider, found := result.globalProviders[provider.Realm()]; found {
			if existingProvider != provider {
				panic("authentication provider overlapping realms")
			}
		} else {
			result.globalProviders[provider.Realm()] = provider
			// If the authentication provider requires some self-managed endpoints, they can be added to the list of exclusions,
			// however, these must be unique and will raise an error if there are conflicting paths. If the authentication
			// provider allows usage of custom endpoints, the authentication provider must configure and report which
			// endpoints should be handled by it.
			for _, endpoint := range provider.Endpoints() {
				if e := result.registeredEndpoints.Add(endpoint, authorizationRules{
					authenticationProviders: []AuthenticationProvider{provider},
				}); e != nil {
					panic("Provider owned endpoint " + endpoint + " already registered")
				}
			}
		}
		// If the authentication provider provides a specific challenge keyword to be returned when unauthenticated
		// access is attempted, it will also be registered in the filter.
		if provider.Challenge() != "" {
			result.challenges = append(result.challenges, fmt.Sprintf("%s realm=\"%s\"", provider.Challenge(), provider.Realm()))
		}
	}

	// If there are any path specific rules to apply, they will be validated beforehand.
	if fb.authorizationBuilders != nil {
		result.authorizations = pathTree.New[authorizationRules]()
		for _, builder := range fb.authorizationBuilders {
			authorization := authorizationRules{
				authenticationProviders: builder.providers,
				authorization:           builder.authorization,
			}
			for _, provider := range builder.providers {
				// like root-level authentication providers, no nil authentication providers are allowed to be added, and they must serve a specific realm
				if provider == nil {
					panic("nil authentication provider")
				} else if provider.Realm() == "" {
					panic("authentication provider with no realm")
				}
				// path specific authentication providers must also serve a unique realm, non-conflicting with root-level realms.
				if existingProvider, found := result.globalProviders[provider.Realm()]; found {
					if existingProvider != provider {
						panic("path authentication provider overloading existing realm")
					}
				} else {
					result.globalProviders[provider.Realm()] = provider
					// any endpoint handled by path specific authentication providers may also not conflict with any other registered path
					for _, endpoint := range provider.Endpoints() {
						if e := result.registeredEndpoints.Add(endpoint, authorization); e != nil {
							panic("Provider owned endpoint already registered")
						}
					}
				}
				// If the authentication provider provides a specific challenge keyword to be returned when unauthenticated, it will be added specifically to the path.
				if provider.Challenge() != "" {
					authorization.challenges = append(authorization.challenges, fmt.Sprintf("%s realm=\"%s\"", provider.Challenge(), provider.Realm()))
				}
			}

			// the configured authorization will be added to all paths configured together.
			for _, path := range builder.paths {
				if e := result.authorizations.Add(path, authorization); e != nil {
					// either the path is invalid or it's overloading an existing path
					panic(e)
				}
			}
		}
	}

	// add authentication triggers to the filter as a whole
	// TODO: separate triggers for root-level authentication and path specific ones, to accommodate authentication filters without root-level authentication
	result.authenticationTriggers = fb.authenticationTriggers

	return result
}

// anonymous adds the given paths to the list of paths handled by the anonymous authentication provider.
// the paths are either added to an existing anonymous provider or a new one is created and added to the list of
// authentication providers. Any path configured to be anonymous at any stage will end up being aggregated to all other
// anonymous paths and will be handled by the special case anonymous authentication provider.
func (fb *filterBuilder) anonymous(paths []string) {
	if len(fb.authenticationProviders) == 0 {
		// if there's still no authentication provider configured, initialize the list with the anonymous provider and the paths
		fb.authenticationProviders = []AuthenticationProvider{anonymousAuthenticationProvider(paths)}

	} else if provider, isAnonymous := fb.authenticationProviders[0].(*anonymousProvider); !isAnonymous {
		// if there is already a list of providers, but without an anonymous provider, add an anonymous provider initialized with the paths
		fb.authenticationProviders = append([]AuthenticationProvider{anonymousAuthenticationProvider(paths)}, fb.authenticationProviders...)

	} else {
		// if there's already an anonymous provider, add the paths to it
		provider.addPaths(paths)
	}
}

// pathSecurityRuleBuilder is a builder for configuring authorization rules applicable to a specific list of paths
type pathSecurityRuleBuilder struct {
	// the filter builder holding this authorization builder
	filterBuilder *filterBuilder
	// List of paths the authorization rules apply to
	paths []string
	// Authorization rules to apply to the paths
	authorization Authorization
	// List of authentication providers available to the paths
	providers []AuthenticationProvider
}

// Anonymous configures the paths to allow anonymous access. It fails if authentication has already been configured for the paths.
func (ab *pathSecurityRuleBuilder) Anonymous() FilterBuilder {
	if len(ab.providers) != 0 {
		panic("anonymous access cannot be configured with path authentication")
	}
	ab.filterBuilder.anonymous(ab.paths)
	return ab.filterBuilder
}

// Authorize applies the set of authorization rules to apply to the paths. The list of rules are aggregated into a single
// authorization rule of type All which requires all rules to be satisfied.
func (ab *pathSecurityRuleBuilder) Authorize(authorizations ...Authorization) FilterBuilder {
	if len(authorizations) != 0 {
		if len(authorizations) == 1 {
			ab.authorization = authorizations[0]
		} else {
			// all authorizations are required
			ab.authorization = all(authorizations)
		}
		// appends the authorization builder to the list of authorization builders in the filter builder
		ab.filterBuilder.authorizationBuilders = append(ab.filterBuilder.authorizationBuilders, ab)
	} else if len(ab.providers) == 0 {
		// when building a filter, a nil Authorization without path authenticators means that the paths should
		// be added to the filters anonymous access list of paths
		ab.filterBuilder.anonymous(ab.paths)
	} else {
		// if at least one authentication provider is configured at the path level and no authorization rules, it means that
		// access to the path requires authentication
		ab.filterBuilder.authorizationBuilders = append(ab.filterBuilder.authorizationBuilders, ab)
	}
	return ab.filterBuilder
}

// Authentication adds the given authentication providers to the list of path authentication providers. An empty list raises a panic.
func (ab *pathSecurityRuleBuilder) Authentication(providers ...AuthenticationProvider) PathSecurityRulesBuilder {
	if len(providers) == 0 {
		panic("no authentication providers provided")
	}
	if len(ab.providers) == 0 {
		ab.providers = providers
	} else {
		ab.providers = append(ab.providers, providers...)
	}
	return ab
}

// Filter creates a new security filter builder to configure a new security filter. It takes a boolean parameter to
// specify if the filter should have restricted access by default (non-anonymous access to any path not explicitly
// configured) or not.
func Filter(restricted bool) FilterBuilder {
	return &filterBuilder{restricted: restricted}
}

// authorizationRules hold any path specific configuration that will be stored in the pathTree
type authorizationRules struct {
	// authenticationProviders is a list of authentication providers that are additionally valid for the path the rules apply to
	authenticationProviders []AuthenticationProvider
	// authorization holds any authorization rules that should apply when accessing the path the rules apply to
	authorization Authorization
	// challenges have http authentication challenge tokens that should be returned if unauthenticated access to the path is attempted
	challenges []string
}

// IsAuthorized is invoked by the filter for any path with specific authorization rules. It will check if the access is
// authorized by checking the authentication status and testing any authorization rules defined for the path.
func (ar *authorizationRules) IsAuthorized(headers http.Header, user *User, scope we.RequestScope) (*User, error) {
	// at this stage, either there is already a user (authenticated at root level or taken from session), or
	// there is no authenticated user.

	// if there's no user yet, we try to authenticate it if there are any authentication providers defined at the path
	// level.
	// TODO: review the path level authentication
	if user == nil {
		var e error
		for _, provider := range ar.authenticationProviders {
			user, e = provider.Authenticate(headers, scope)
			if user != nil {
				// a user is authenticated, we add the realm to it
				user.Realm = provider.Realm()
			}
			if e != nil {
				return user, e
			} else {
				break
			}
		}
		// still no user is present, if there are also no authorization rules, we fail immediately
		if user == nil && ar.authorization == nil {
			return nil, events.UnauthorizedError
		}
	}

	// A user was authenticated, if there are authorization rules...
	if ar.authorization == nil || ar.authorization.IsAuthorized(user, scope) {
		return user, nil
	}

	return user, events.ForbiddenError

}

// sendChallenge is a help function to add authentication challenges to the response headers
func sendChallenges(headers http.Header, challenges []string) {
	for _, challenge := range challenges {
		headers.Add("WWW-Authenticate", challenge)
	}
}

// filter is a we.Filter implementation that will handle authentication and authorization access.
type filter struct {
	// globalProviders is a map of all authentication providers configured for the filter. The key is the realm that
	// the provider will serve.
	globalProviders map[string]AuthenticationProvider
	// list of root-level authentication providers
	authenticationProviders []AuthenticationProvider
	// list of trigger functions that should be invoked on a successful user authentication
	authenticationTriggers []func(*User, we.RequestScope)
	// list of exclusion endpoints that should be ignored for authorization checks as they will be directly handled by
	// authorization providers
	registeredEndpoints pathTree.Tree[authorizationRules]
	// path tree containing all paths with specific authorization rules and the corresponding authorization rules that
	// need to be validated
	authorizations pathTree.Tree[authorizationRules]
	// root level authorization challenges that should be returned if unauthenticated access to restricted paths is attempted
	challenges []string
	// if access to any path that is not configured in the authorizations path tree should be denied by default
	restricted bool
}

// Filter is the implementation of the we.Filter method. It will handle the authentication and authorization process of
// any request that passes through it. The authentication can either be stateful, if we sessions are turned on, or
// stateless, if no sessions are configured. If stateful, the authentication mechanism may be skipped if there's still
// a valid user in session, while any authorizations applicable to the accessed path will still be checked.
func (f *filter) Filter(header http.Header, scope we.RequestScope) error {
	var user, sessionUser *User

	// let's first check if there might be a user in session and if it's valid
	if storedUser := scope.GetFromSession(UserAttributeName); storedUser != nil {
		isUser := false
		// User/Programmer may actually overwrite the user in session with some other object. If it's not a user
		// object stored in the expected key, then we consider it invalid (unauthenticated) and remove it from the session.
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
			// If there are authorization rules for the path, we simply check if access is authorized. Either access
			// needs to be authenticated or anonymous access is allowed.
			user, e = (*authorization).IsAuthorized(header, user, scope)
			if user != nil {
				// Successful authorization will always return a user, either a real one or the special anonymous user.
				for _, trigger := range f.authenticationTriggers {
					// trigger any configured authentication trigger functions
					execute(trigger, user, scope)
				}
				// set the user in session, which, in case WE has no sessions turned on, will be lost at the end of the request.
				scope.SetInSession(UserAttributeName, user)
			}

			// If either access to the path requires an authenticated user, or an authentication attempt was made
			// with invalid credentials, isAuthorized() will return an error. If it doesn't return an error it's because
			// authentication at root-level may still be attempted.
			if e != nil {
				// The user simply is not authorized.
				if e == events.UnauthorizedError {
					sendChallenges(header, f.challenges)
				}
				// Any other error is considered a failed authentication attempt
				return e
			}
		}

		// let's check if the request can be authenticated at root level, in case there's still no user
		if user == nil {
			for _, provider := range f.authenticationProviders {
				if authenticatedUser, e := provider.Authenticate(header, scope); e != nil {
					return e
				} else if authenticatedUser != nil {
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

	if user != nil && user != Anonymous {
		scope.Set(UserAttributeName, user)
		if sessionUser != user {
			scope.SetInSession(UserAttributeName, user)
		}
		for _, trigger := range f.authenticationTriggers {
			execute(trigger, user, scope)
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

// execute triggers an onAuthentication trigger function, recovering from any panics the execution may trigger.
func execute(trigger func(*User, we.RequestScope), user *User, scope we.RequestScope) {
	defer func() {
		if recovery := recover(); recovery != nil {
			fmt.Println("failed to call authentication trigger", recovery)
		}
	}()
	trigger(user, scope)
}
