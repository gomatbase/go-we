// Copyright 2023 GOM. All rights reserved.
// Since 29/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
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
	ValidateAuthorizationCode(code, replyHandlerUrl string) (*User, error)
}

type SSOAuthenticationProviderBuilder interface {
	RedirectToRequestedUrl(redirect bool) SSOAuthenticationProviderBuilder
	Address(string) SSOAuthenticationProviderBuilder
	DynamicAddress(dynamic bool) SSOAuthenticationProviderBuilder
	DefaultAuthenticatedEndpoint(string) SSOAuthenticationProviderBuilder
	Realm(string) SSOAuthenticationProviderBuilder
	AuthorizationCodeProvider(AuthorizationCodeProvider) SSOAuthenticationProviderBuilder
	AuthorizationReplyHandler(string) SSOAuthenticationProviderBuilder
	Build() AuthenticationProvider
}

type ssoAuthenticationProviderBuilder struct {
	provider *ssoAuthenticationProvider
}

func (sapb *ssoAuthenticationProviderBuilder) DynamicAddress(dynamic bool) SSOAuthenticationProviderBuilder {
	sapb.provider.dynamicBaseUrl = dynamic
	return sapb
}

func (sapb *ssoAuthenticationProviderBuilder) RedirectToRequestedUrl(redirect bool) SSOAuthenticationProviderBuilder {
	sapb.provider.chainAuthenticatedEndpoint = !redirect
	return sapb
}

func (sapb *ssoAuthenticationProviderBuilder) Address(publicAddress string) SSOAuthenticationProviderBuilder {
	if len(publicAddress) == 0 {
		panic("public address cannot be empty")
	}
	if publicUrl, e := url.Parse(publicAddress); e != nil {
		panic("Invalid url for public address")
	} else if publicUrl.Opaque != "" {
		panic("opaque urls are not supported for public address")
	} else {
		// let's make sure the url is clean and revert to string
		publicUrl.Path = ""
		publicUrl.RawPath = ""
		publicUrl.RawQuery = ""
		publicUrl.Fragment = ""
		publicUrl.User = nil
		sapb.provider.address = publicUrl.String()
	}

	return sapb
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
	sapb.provider.otps = make(map[string]*User)
	return sapb.provider
}

func SSOAuthenticationProvider() SSOAuthenticationProviderBuilder {
	return &ssoAuthenticationProviderBuilder{provider: &ssoAuthenticationProvider{}}
}

type ssoAuthenticationProvider struct {
	realm                     string
	authorizationCodeProvider AuthorizationCodeProvider
	replyHandlerEndpoint      string

	authorizationRequests      map[string]*url.URL
	otps                       map[string]*User
	defaultEndpoint            string
	addressSchema              string
	addressHost                string
	address                    string
	chainAuthenticatedEndpoint bool
	dynamicBaseUrl             bool
}

func (sap *ssoAuthenticationProvider) Authenticate(headers http.Header, scope we.RequestScope) (*User, error) {
	// let's check if we're handling a reply from an authorization code request
	request := scope.Request()
	requestUrl := scope.Request().URL
	if requestUrl.Path == sap.replyHandlerEndpoint {
		requestId, authorizationCode := sap.authorizationCodeProvider.State(request)
		originalDestination, found := sap.authorizationRequests[requestId]
		if !found {
			// in case this might be a redirection mistake, the authenticated redirection should go back to the default endpoint
			requestUrl.Path = sap.baseUrl(scope.Request()) + sap.defaultEndpoint
			requestUrl.RawQuery = ""
		} else {
			delete(sap.authorizationRequests, requestId)
			headers.Set("Content-Location", originalDestination.String())

			if user, e := sap.authorizationCodeProvider.ValidateAuthorizationCode(authorizationCode, sap.redirectUrl(request)); e != nil {
				return nil, events.UnauthorizedError
			} else if user == nil {
				return nil, events.UnauthorizedError
			} else if sap.chainAuthenticatedEndpoint {
				// override the request path to the original request
				return user, events.Continue
			} else {
				if !scope.HasSession() {
					// There are no sessions in place, let's provide an OTP through a query parameter
					otp := uuid.NewString()
					sap.otps[otp] = user
					q := originalDestination.Query()
					q.Add("otp", otp)
					originalDestination.RawQuery = q.Encode()
				}
				return user, events.FoundRedirect.WithAttribute(originalDestination.String())
			}
		}
	}

	// we check if there's an OTP in the request, which would be the case when there's no sessions active and the
	// authorization should redirect to the original destination
	if otp, found := scope.LookupParameters("otp"); found {
		if user, found := sap.otps[otp[0]]; found {
			delete(sap.otps, otp[0])
			return user, nil
		} else {
			// not found, might be a redresh. Let's remove the otp and redirect to the requested url
			q := requestUrl.Query()
			q.Del("otp")
			requestUrl.RawQuery = q.Encode()
		}
	}

	// this authorization provider is meant to either use the user in session, or redirect to the authorization server
	requestId := uuid.NewString()
	// the request doesn't have the scheme and host of the request, let's fill it and store it for later autentication redirection
	request.URL.Scheme, request.URL.Host, _ = sap.baseUrlSchemeAndHost(request)
	sap.authorizationRequests[requestId] = request.URL
	return nil, events.FoundRedirect.WithAttribute(sap.authorizationCodeProvider.AuthorizationUrl(sap.redirectUrl(request), requestId))
}

func (sap *ssoAuthenticationProvider) redirectUrl(request *http.Request) string {
	return sap.baseUrl(request) + sap.replyHandlerEndpoint
}

func (sap *ssoAuthenticationProvider) baseUrl(request *http.Request) string {
	if len(sap.address) == 0 || sap.dynamicBaseUrl {
		_, _, address := sap.baseUrlSchemeAndHost(request)
		return address
	}
	return sap.address
}

func (sap *ssoAuthenticationProvider) baseUrlSchemeAndHost(request *http.Request) (scheme string, host string, address string) {
	if sap.dynamicBaseUrl || len(sap.addressSchema) == 0 || len(sap.addressHost) == 0 {
		if forwarded := request.Header.Get("Forwarded"); len(forwarded) > 0 {
			// Forwarded header is present, let's try to use it
			segments := strings.Split(forwarded, ";")
			scheme, host = extractSchemaAndHost(segments)
			if len(scheme) == 0 {
				// let's default to https
				scheme = "https"
			}
		} else if host = request.Header.Get("X-Forwarded-Host"); len(host) > 0 {
			scheme = request.Header.Get("X-Forwarded-Proto")
			if len(scheme) == 0 {
				// let's default to https
				scheme = "https"
			}
		} else {
			// no forwarded headers, let's try to use the request url
			host = request.Host
			if request.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}

		address = fmt.Sprintf("%s://%s", scheme, host)
		if sap.dynamicBaseUrl {
			sap.addressSchema = scheme
			sap.addressHost = host
			sap.address = address
		}
	}
	return
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

func (sap *ssoAuthenticationProvider) Endpoints() []string {
	return []string{sap.replyHandlerEndpoint}
}

func extractSchemaAndHost(segments []string) (schema string, host string) {
	missing := 2
	for _, segment := range segments {
		if strings.HasPrefix(segment, "proto=") {
			schema = segment[6:]
			missing--
		} else if strings.HasPrefix(segment, "host=") {
			host = segment[5:]
			missing--
		}
		if missing == 0 {
			// if there are appended forwarded segments, we should ignore them
			return
		}
	}
	return
}
