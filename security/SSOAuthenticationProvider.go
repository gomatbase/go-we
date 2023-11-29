// Copyright 2023 GOM. All rights reserved.
// Since 29/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"net/http"
	"net/url"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/errors"
	"github.com/google/uuid"
)

const (
	DefaultRealm                             = "SSO"
	DefaultAuthorizationReplyHandlerEndpoint = "/sso/authorization"
	DefaultAuthenticatedEndpoint             = "/"
)

type AuthorizationCodeProvider interface {
	AuthorizationUrl(replyHandlerUrl, state string) string
	State(*http.Request) (state string, accessCode string)
	ValidateAuthorizationCode(code string) (*User, error)
}

type SSOAuthenticationProviderBuilder interface {
	DefaultAuthenticatedEndpoint(string) SSOAuthenticationProviderBuilder
	Realm(string) SSOAuthenticationProviderBuilder
	AuthorizationCodeProvider(AuthorizationCodeProvider) SSOAuthenticationProviderBuilder
	AuthorizationReplyHandler(string) SSOAuthenticationProviderBuilder
	Build() AuthenticationProvider
}

type ssoAuthenticationProviderBuilder struct {
	provider *ssoAuthenticationProvider
}

func (sapb *ssoAuthenticationProviderBuilder) DefaultAuthenticatedEndpoint(endpoint string) SSOAuthenticationProviderBuilder {
	if len(endpoint) == 0 {
		panic("default authenticated endpoint cannot be empty")
	} else if endpoint[0] != '/' {
		endpoint = "/" + endpoint
	}
	sapb.provider.defaultEndpoint = endpoint
	return sapb
}

func (sapb *ssoAuthenticationProviderBuilder) Realm(realm string) SSOAuthenticationProviderBuilder {
	if len(realm) == 0 {
		panic("realm cannot be empty")
	}
	sapb.provider.realm = realm
	return sapb
}

func (sapb *ssoAuthenticationProviderBuilder) AuthorizationCodeProvider(provider AuthorizationCodeProvider) SSOAuthenticationProviderBuilder {
	if provider == nil {
		panic("authorization code provider cannot be nil")
	}
	sapb.provider.authorizationCodeProvider = provider
	return sapb
}

func (sapb *ssoAuthenticationProviderBuilder) AuthorizationReplyHandler(endpoint string) SSOAuthenticationProviderBuilder {
	if len(endpoint) == 0 {
		panic("authorization reply handler endpoint cannot be empty")
	} else if endpoint[0] != '/' {
		endpoint = "/" + endpoint
	}
	if len(endpoint) == 1 {
		panic("authorization reply handler endpoint cannot be root")
	}
	sapb.provider.replyHandlerEndpoint = endpoint
	return sapb
}

func (sapb *ssoAuthenticationProviderBuilder) Build() AuthenticationProvider {
	if len(sapb.provider.realm) == 0 {
		sapb.provider.realm = DefaultRealm
	}
	if len(sapb.provider.replyHandlerEndpoint) == 0 {
		sapb.provider.replyHandlerEndpoint = DefaultAuthorizationReplyHandlerEndpoint
	}
	if sapb.provider.authorizationCodeProvider == nil {
		panic("authorization code provider is required")
	}
	if len(sapb.provider.defaultEndpoint) == 0 {
		sapb.provider.defaultEndpoint = DefaultAuthenticatedEndpoint
	}
	sapb.provider.authorizationRequests = make(map[string]*url.URL)
	return sapb.provider
}

func SSOAuthenticationProvider() SSOAuthenticationProviderBuilder {
	return &ssoAuthenticationProviderBuilder{provider: &ssoAuthenticationProvider{}}
}

type ssoAuthenticationProvider struct {
	realm                     string
	authorizationCodeProvider AuthorizationCodeProvider
	replyHandlerEndpoint      string

	authorizationRequests map[string]*url.URL
	defaultEndpoint       string
}

func (sap *ssoAuthenticationProvider) Authenticate(headers http.Header, scope we.RequestScope) (*User, error) {
	// let's check if were handling a reply from an authorization code request
	request := scope.Request()
	requestUrl := scope.Request().URL
	if requestUrl.Path == sap.replyHandlerEndpoint {
		requestId, authorizationCode := sap.authorizationCodeProvider.State(request)
		redirectingUrl, found := sap.authorizationRequests[requestId]
		if !found {
			// in case this might be a redirection mistake, the authenticated redirection should go back to the default endpoint
			requestUrl.Path = sap.defaultEndpoint
			requestUrl.RawQuery = ""
		} else {
			delete(sap.authorizationRequests, requestId)
			if user, e := sap.authorizationCodeProvider.ValidateAuthorizationCode(authorizationCode); e != nil {
				return nil, errors.UnauthorizedError.WithPayload("text/plain", e.Error())
			} else if user == nil {
				return nil, errors.UnauthorizedError
			} else {
				// override the request path to the original request
				location := redirectingUrl.Path
				if len(redirectingUrl.RawQuery) > 0 {
					location = location + "?" + redirectingUrl.RawQuery
				}
				headers.Set("Content-Location", location)
				request.URL = redirectingUrl
				return user, nil
			}
		}
	}

	// this authorization provider is meant to either use the user in session, or redirect to the authorization server
	requestId := uuid.NewString()
	sap.authorizationRequests[requestId] = requestUrl
	headers.Set("Location", sap.authorizationCodeProvider.AuthorizationUrl(sap.replyHandlerEndpoint, requestId))
	return nil, errors.FoundRedirect
}

func (sap *ssoAuthenticationProvider) Realm() string {
	return sap.realm
}

func (sap *ssoAuthenticationProvider) IsValid(user *User) bool {
	if user == nil {
		return false
	}
	// trust the security filter to validate a user authorized by this authentication provider.
	return true
}

func (sap *ssoAuthenticationProvider) Challenge() string {
	// no sense in providing a challenge for SSO, it should redirect to the authorization server for an authorization code
	return ""
}
