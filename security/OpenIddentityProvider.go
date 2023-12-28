// Copyright 2023 GOM. All rights reserved.
// Since 22/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	err "github.com/gomatbase/go-error"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	AuthorizationCodeUrl = "%s?response_type=code%s&client_id=%s&redirect_uri=%s&state=%s"
	ScopesQueryParameter = "&scope=%s"

	UnsupportedKeyType    = err.ErrorF("unsupported key type: %s")
	ModulusDecodingError  = err.ErrorF("error decoding key %s modulus: %v")
	ExponentDecodingError = err.ErrorF("error decoding key %s exponent: %v")
	NoJwksUriError        = err.ErrorF("unable to refresh. no jwks uri provided")
	FailedToRefreshJwks   = err.ErrorF("failed to refresh jwks: %v")
	InvalidClainsError    = err.ErrorF("invalid claims: %s")
)

type UserEnrichmentFunction func(*User) (*User, error)

type OpenIdConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JwksUri                                    string   `json:"jwks_uri"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ServiceDocumentation                       string   `json:"service_documentation"`
	UiLocalesSupported                         []string `json:"ui_locales_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
}

type TokenIntrospection struct {
	Raw        []byte         `json:"-"`
	RawMap     map[string]any `json:"-"`
	Active     bool           `json:"active"`
	Scope      any            `json:"scope"`
	Scopes     []string       `json:"-"`
	ClientId   string         `json:"client_id"`
	Username   string         `json:"username"`
	Type       string         `json:"token_type"`
	Expiration int64          `json:"exp"`
	Issued     int64          `json:"iat"`
	Starting   int64          `json:"nbf"`
	Subject    string         `json:"sub"`
	Audience   any            `json:"aud"`
	Audiences  []string       `json:"-"`
	Issuer     string         `json:"iss"`
	TokenId    string         `json:"jti"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type TokenData struct {
	Raw           string
	Claims        *jwt.MapClaims
	Introspection *TokenIntrospection
}

type ClaimsMapper func(claims *jwt.MapClaims) (*User, error)

var DefaultClaimsMapper = func(claims *jwt.MapClaims) (*User, error) {
	if claims == nil {
		return nil, InvalidClainsError.WithValues("no claims")
	}

	user := &User{Data: claims, Active: true}
	isType := true
	if value, found := (*claims)["sub"]; !found {
		return nil, InvalidClainsError.WithValues("claims has no subject")
	} else if user.OriginId, isType = value.(string); !isType {
		return nil, InvalidClainsError.WithValues("subject is not a string")
	}
	user.Username = user.OriginId
	if value, found := (*claims)["iss"]; found {
		if user.Origin, isType = value.(string); !isType {
			return nil, InvalidClainsError.WithValues("issuer is not a string")
		}
	}
	if value, found := (*claims)["scope"]; found {
		var e error
		user.Scopes, e = translateScopes(value)
		if e != nil {
			return nil, e
		}
	}

	return user, nil
}

type JwKeys struct {
	Keys []JwKey `json:"keys"`
}

// JwKey represents a json web key for RSA keys (at the moment only RSA keys are supported)
type JwKey struct {
	Id        string   `json:"kid"`
	Type      string   `json:"kty"`
	Algorithm string   `json:"alg"`
	Use       string   `json:"use"`
	Modulus   string   `json:"n"`
	Exponent  string   `json:"e"`
	X5TS256   string   `json:"x5t#S256,omitempty"`
	X5T       string   `json:"x5t,omitempty"`
	X5C       []string `json:"x5c,omitempty"`
}

type BearerAndSsoProvider interface {
	TokenIntrospector
	AuthorizationCodeProvider
	TokenIntrospector() TokenIntrospector
	AuthorizationCodeProvider() AuthorizationCodeProvider
}

type OpenIdIdentityProviderBuilder interface {
	OpenIdConfigurationEndpoint(path string) OpenIdIdentityProviderBuilder
	IntrospectionEndpoint(path string) OpenIdIdentityProviderBuilder
	UserEnrichment(function UserEnrichmentFunction) OpenIdIdentityProviderBuilder
	TokenEndpoint(path string) OpenIdIdentityProviderBuilder
	JwksEndpoint(path string) OpenIdIdentityProviderBuilder
	Jwks(jwks []JwKey) OpenIdIdentityProviderBuilder
	JwtValidationFallback(fallbackToIntrospection bool) OpenIdIdentityProviderBuilder
	ClaimsMapper(mapper ClaimsMapper) OpenIdIdentityProviderBuilder
	Scope(scope ...string) OpenIdIdentityProviderBuilder
	Client(client, secret string) OpenIdIdentityProviderBuilder
	Tls(config *tls.Config) OpenIdIdentityProviderBuilder
	Build() BearerAndSsoProvider
}

func OpenIdIdentityProvider(openIdUrl string) OpenIdIdentityProviderBuilder {
	if u, e := url.Parse(openIdUrl); e != nil || u.Scheme == "" || u.Host == "" {
		panic(fmt.Sprintf("invalid open id url: %s", openIdUrl))
	}
	return &openIdIdentityProviderBuilder{openIdUrl: openIdUrl, provider: &openIdIdentityProvider{}}
}

type openIdIdentityProviderBuilder struct {
	openIdUrl                   string
	openIdConfigurationEndpoint string
	introspectionEndpoint       string
	tokenEndpoint               string
	jwksEndpoint                string
	scopes                      []string
	jwks                        []JwKey
	tlsConfig                   *tls.Config
	provider                    *openIdIdentityProvider
}

func (oipb *openIdIdentityProviderBuilder) UserEnrichment(function UserEnrichmentFunction) OpenIdIdentityProviderBuilder {
	oipb.provider.userEnrichmentFunction = function
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) Scope(scope ...string) OpenIdIdentityProviderBuilder {
	oipb.scopes = scope
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) OpenIdConfigurationEndpoint(path string) OpenIdIdentityProviderBuilder {
	oipb.openIdConfigurationEndpoint = path
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) IntrospectionEndpoint(path string) OpenIdIdentityProviderBuilder {
	oipb.introspectionEndpoint = path
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) TokenEndpoint(path string) OpenIdIdentityProviderBuilder {
	oipb.tokenEndpoint = path
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) JwksEndpoint(path string) OpenIdIdentityProviderBuilder {
	oipb.jwksEndpoint = path
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) Jwks(jwks []JwKey) OpenIdIdentityProviderBuilder {
	if len(jwks) == 0 {
		panic("empty set of keys")
	}
	oipb.jwks = jwks
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) JwtValidationFallback(fallbackToIntrospection bool) OpenIdIdentityProviderBuilder {
	oipb.provider.allowIntrospectionIfInvalid = fallbackToIntrospection
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) ClaimsMapper(mapper ClaimsMapper) OpenIdIdentityProviderBuilder {
	if mapper == nil {
		panic("claims mapper cannot be nil")
	}
	oipb.provider.claimsMapper = mapper
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) Client(client, secret string) OpenIdIdentityProviderBuilder {
	oipb.provider.client = client
	oipb.provider.secret = secret
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) Tls(config *tls.Config) OpenIdIdentityProviderBuilder {
	oipb.tlsConfig = config
	return oipb
}

func (oipb *openIdIdentityProviderBuilder) Build() BearerAndSsoProvider {
	if oipb.openIdUrl[len(oipb.openIdUrl)-1] == '/' {
		oipb.openIdUrl = oipb.openIdUrl[:len(oipb.openIdUrl)-1]
	}
	// we try to get the openId configuration. If a specific endpoint is provided, the build will fail if the endpoint
	// doesn't exist or returns invalid open id configuration. If not, try to get the configuration from the .well-known
	// endpoint only fail if the builder provides no required configuration either, like the token endpoint.
	mustExist := true
	if len(oipb.openIdConfigurationEndpoint) == 0 {
		oipb.openIdConfigurationEndpoint = "/.well-known/openid-configuration"
		mustExist = false
	} else if oipb.openIdConfigurationEndpoint[0] != '/' {
		oipb.openIdConfigurationEndpoint = "/" + oipb.openIdConfigurationEndpoint
	}

	request, e := http.NewRequest("GET", oipb.openIdUrl+oipb.openIdConfigurationEndpoint, nil)
	if e != nil {
		// most probably an incorrect configuration endpoint
		panic(e)
	}
	client := http.DefaultClient
	if oipb.tlsConfig != nil {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: oipb.tlsConfig}}
	}

	response, openIdConfigurationError := client.Do(request)
	if openIdConfigurationError == nil {
		if response.StatusCode != http.StatusOK {
			openIdConfigurationError = errors.New("unexpected response for open id configuration endpoint")
		} else {
			openIdConfigurationError = json.NewDecoder(response.Body).Decode(&oipb.provider.openIdConfiguration)
		}
	}
	// only fail at this point if the configuration endpoint has been explicitly given
	if openIdConfigurationError != nil && mustExist {
		panic(openIdConfigurationError)
	}

	oipb.provider.canIntrospect = true
	if len(oipb.tokenEndpoint) > 0 {
		oipb.provider.openIdConfiguration.TokenEndpoint = oipb.openIdUrl + oipb.tokenEndpoint
		if _, e = url.Parse(oipb.provider.openIdConfiguration.TokenEndpoint); e != nil {
			panic(fmt.Sprintf("invalid open token endpoint: %s", oipb.provider.openIdConfiguration.TokenEndpoint))
		}
	} else if len(oipb.provider.openIdConfiguration.TokenEndpoint) == 0 {
		// no token endpoint provided, we can't introspect
		oipb.provider.canIntrospect = false
	}

	if oipb.provider.canIntrospect {
		// it's possible to login with the open id server, let's setup the introspection endpoint
		if len(oipb.introspectionEndpoint) == 0 {
			oipb.introspectionEndpoint = "/introspect"
		}
		if oipb.introspectionEndpoint[0] != '/' {
			oipb.introspectionEndpoint = "/" + oipb.introspectionEndpoint
		}
		oipb.provider.introspectionEndpoint = oipb.openIdUrl + oipb.introspectionEndpoint
		if _, e = url.Parse(oipb.provider.introspectionEndpoint); e != nil {
			panic(fmt.Sprintf("invalid token introspection endpoint: %s", oipb.provider.introspectionEndpoint))
		}

		if len(oipb.provider.client) == 0 || len(oipb.provider.secret) == 0 {
			// we can't introspect after all
			oipb.provider.canIntrospect = false
			oipb.provider.httpClient = client
		} else {
			cc := clientcredentials.Config{
				ClientID:     oipb.provider.client,
				ClientSecret: oipb.provider.secret,
				TokenURL:     oipb.provider.openIdConfiguration.TokenEndpoint,
			}
			oipb.provider.httpClient = cc.Client(context.WithValue(context.Background(), oauth2.HTTPClient, client))
		}
	} else {
		// use a standard client to get the jwks
		oipb.provider.httpClient = client
	}

	oipb.provider.canValidate = true
	if len(oipb.jwks) == 0 {
		// no list of validation keys is provided, let's see if we can get it from the open id server
		if len(oipb.jwksEndpoint) > 0 {
			// a specific jwks endpoint is provided, takes precedence
			if oipb.jwksEndpoint[0] != '/' {
				oipb.jwksEndpoint = "/" + oipb.jwksEndpoint
			}
			oipb.provider.openIdConfiguration.JwksUri = oipb.openIdUrl + oipb.jwksEndpoint
			if _, e = url.Parse(oipb.provider.openIdConfiguration.JwksUri); e != nil {
				panic(fmt.Sprintf("invalid jwks endpoint: %s", oipb.provider.openIdConfiguration.JwksUri))
			}
		}
		if e = oipb.provider.refreshJwks(); e != nil {
			oipb.provider.canValidate = false
		}
	} else if e = oipb.provider.setKeys(oipb.jwks); e != nil {
		panic(e)
	}

	// Can only check authorization codes if the token endpoint is available and credentials are given, which is the
	// case if token introspection is possible
	oipb.provider.canCheckCodes = len(oipb.provider.openIdConfiguration.AuthorizationEndpoint) > 0 && oipb.provider.canIntrospect

	if oipb.provider.canValidate {
		oipb.provider.jwtParser = jwt.NewParser()
		if oipb.provider.claimsMapper == nil {
			oipb.provider.claimsMapper = DefaultClaimsMapper
		}
	}

	if len(oipb.scopes) > 0 {
		oipb.provider.requestScopes = fmt.Sprintf(ScopesQueryParameter, url.PathEscape(strings.Join(oipb.scopes, " ")))
	}

	return oipb.provider
}

/*
the identity provider should have a client_credentials token to interact with the oauth2 server.

With that, it should be able to introspect the token to get all scopes/roles. the provided token, if
jwt, should be validated using the exposed jwk endpoint.
*/
type openIdIdentityProvider struct {
	client     string
	secret     string
	httpClient *http.Client

	openIdConfiguration OpenIdConfiguration

	canCheckCodes bool
	requestScopes string

	jwks                        map[string]any
	introspectionEndpoint       string
	allowIntrospectionIfInvalid bool
	canValidate                 bool
	canIntrospect               bool
	jwtParser                   *jwt.Parser
	claimsMapper                ClaimsMapper
	authorizationTokenFormat    string
	userEnrichmentFunction      UserEnrichmentFunction
}

func (oip *openIdIdentityProvider) AuthorizationUrl(replyHandlerUrl, state string) string {
	return fmt.Sprintf(AuthorizationCodeUrl, oip.openIdConfiguration.AuthorizationEndpoint, oip.requestScopes, oip.client, url.QueryEscape(replyHandlerUrl), state)
}

func (oip *openIdIdentityProvider) State(request *http.Request) (state string, accessCode string) {
	q := request.URL.Query()
	return q.Get("state"), q.Get("code")
}

func (oip *openIdIdentityProvider) ValidateAuthorizationCode(code, replyHandlerUrl string) (user *User, e error) {
	b := fmt.Sprintf("grant_type=authorization_code&token_format=%s&client_id=%s%s&code=%s&redirect_uri=%s", oip.authorizationTokenFormat, oip.client, oip.requestScopes, code, replyHandlerUrl)
	request, e := http.NewRequest("POST", oip.openIdConfiguration.TokenEndpoint,
		bytes.NewReader([]byte(b)))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := oip.httpClient.Do(request)
	if e != nil {
		return nil, e
	}
	body, e := io.ReadAll(response.Body)
	tokenResponse := &TokenResponse{}
	if e = json.Unmarshal(body, tokenResponse); e != nil {
		return nil, e
	}

	if user, e = oip.Introspect(tokenResponse.AccessToken); e != nil {
		return nil, e
	} else if oip.userEnrichmentFunction != nil {
		user, e = oip.userEnrichmentFunction(user)
	}
	return
}

func (oip *openIdIdentityProvider) TokenIntrospector() TokenIntrospector {
	if !oip.canIntrospect && !oip.canValidate {
		panic("no means to validate a token")
	}
	return oip
}

func (oip *openIdIdentityProvider) AuthorizationCodeProvider() AuthorizationCodeProvider {
	if !oip.canCheckCodes {
		panic("no means to validate an authorization code")
	}
	return oip
}

func (oip *openIdIdentityProvider) isValidJwtToken(token string) (*jwt.Token, error) {
	jwtToken, segments, e := oip.jwtParser.ParseUnverified(token, &jwt.MapClaims{})
	if e == nil {
		// it's a valid jwt token, let's verify it
		key, ok := oip.jwks[jwtToken.Header["kid"].(string)]
		if !ok {
			// the key is not cached, let's try to refresh the jwks. if there's an error the keys will simply not be refreshed
			_ = oip.refreshJwks()
			if key, ok = oip.jwks[jwtToken.Header["kid"].(string)]; !ok {
				// still not found, let's fail
				return jwtToken, errors.New("invalid signing key")
			}
		}

		signature, e := oip.jwtParser.DecodeSegment(segments[2])
		if e != nil {
			return nil, e
		}
		e = jwtToken.Method.Verify(strings.Join(segments[0:2], "."), signature, key)
		return jwtToken, e
	}
	return nil, e
}

func (oip *openIdIdentityProvider) Introspect(token string) (*User, error) {

	// if we allow validating the token through the signature, then try to validate the jwt, if not go directly to calling the introspection service.
	if oip.canValidate {
		jwtToken, e := oip.isValidJwtToken(token)
		if e == nil {
			if user, e := oip.claimsMapper(jwtToken.Claims.(*jwt.MapClaims)); e != nil {
				return nil, e
			} else {
				user.Data = &TokenData{
					Raw:    token,
					Claims: jwtToken.Claims.(*jwt.MapClaims),
				}
				return user, nil
			}
		} else if jwtToken != nil && !oip.allowIntrospectionIfInvalid {
			// if we don't allow introspecting when the token is invalid, return the error immediately
			return nil, e
		}
	}

	// either it's not a jwt, the token is not valid, or we should always introspect.
	// The endpoint should be already validated and we can ignore the error
	request, _ := http.NewRequest("POST", oip.introspectionEndpoint, bytes.NewReader([]byte("token="+token)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := oip.httpClient.Do(request)
	if e != nil {
		return nil, e
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("invalid response from introspection endpoint")
	}
	body, e := io.ReadAll(response.Body)
	introspection := &TokenIntrospection{}
	if e = json.Unmarshal(body, introspection); e != nil {
		return nil, e
	}

	if !introspection.Active {
		return nil, errors.New("token is not active")
	}

	introspection.Scopes, _ = translateScopes(introspection.Scope)

	return &User{
		Username: introspection.Username,
		Scopes:   introspection.Scopes,
		Origin:   introspection.Issuer,
		Active:   introspection.Active,
		Data: &TokenData{
			Raw:           token,
			Introspection: introspection,
		},
	}, nil
}

func (oip *openIdIdentityProvider) setKeys(keys []JwKey) error {
	keyMap := make(map[string]any)
	for _, key := range keys {
		switch key.Type {
		case "RSA":
			if modulus, e := base64.RawURLEncoding.DecodeString(key.Modulus); e != nil {
				return ModulusDecodingError.WithValues(key.Id, e)
			} else if exponent, e := base64.RawURLEncoding.DecodeString(key.Exponent); e != nil {
				return ExponentDecodingError.WithValues(key.Id, e)
			} else {
				var buffer bytes.Buffer
				buffer.WriteByte(0)
				buffer.Write(exponent)

				keyMap[key.Id] = &rsa.PublicKey{
					N: (&big.Int{}).SetBytes(modulus),
					E: int(binary.BigEndian.Uint32(buffer.Bytes())),
				}
			}
		default:
			return UnsupportedKeyType.WithValues(key.Type)
		}
	}

	oip.jwks = keyMap
	return nil
}

// refreshJwks tries to load the keys from the openId server. If it fails it will simply not update the cached keys
// and if triggered due to a token validation signed by an unknown key, it will end up failing the validation.
func (oip *openIdIdentityProvider) refreshJwks() error {
	if len(oip.openIdConfiguration.JwksUri) == 0 {
		return NoJwksUriError
	}

	jwks := &JwKeys{}
	// at this stage the url was validated, no need to check for errors
	request, _ := http.NewRequest("GET", oip.openIdConfiguration.JwksUri, nil)
	if response, e := oip.httpClient.Do(request); e != nil {
		return FailedToRefreshJwks.WithValues(e)
	} else if response.StatusCode != http.StatusOK {
		return FailedToRefreshJwks.WithValues(response.StatusCode)
	} else if e = json.NewDecoder(response.Body).Decode(jwks); e != nil {
		return e
	}

	return oip.setKeys(jwks.Keys)
}

func ifNil(value, defaultValue any) any {
	if value == nil {
		return defaultValue
	}
	return value
}

func translateScopes(scope any) (scopes []string, e error) {
	switch scope.(type) {
	case []string:
		scopes = scope.([]string)
	case string:
		scopes = strings.Split(scope.(string), " ")
	case []any:
		scopes = make([]string, len(scope.([]any)))
		for i, s := range scope.([]any) {
			scopes[i], _ = s.(string)
		}
	default:
		e = InvalidClainsError.WithValues("scope is not a string nor a list of strings")
	}
	return
}
