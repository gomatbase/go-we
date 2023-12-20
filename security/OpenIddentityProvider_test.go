// Copyright 2023 GOM. All rights reserved.
// Since 22/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gomatbase/go-we/security"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Jti         string `json:"jti"`
}

var tokenResponse, _ = json.Marshal(&TokenResponse{
	AccessToken: "h493hsiuhfg93h4gf",
	TokenType:   "bearer",
	ExpiresIn:   419999,
	Scope:       "openid",
	Jti:         "0",
})

var (
	prvKey      *rsa.PrivateKey
	jwKey       security.JwKey
	jwksBody    []byte
	oldJwksBody []byte
)

func init() {
	prvKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	jwKey = security.JwKey{
		Id:        "OLD",
		Type:      "RSA",
		Algorithm: "RS256",
		Use:       "sig",
		Modulus:   base64.RawURLEncoding.EncodeToString(prvKey.PublicKey.N.Bytes()),
		Exponent:  base64.RawURLEncoding.EncodeToString([]byte{byte(prvKey.PublicKey.E >> 16), byte(prvKey.PublicKey.E >> 8), byte(prvKey.PublicKey.E)}),
	}
	oldJwksBody, _ = json.Marshal(&security.JwKeys{
		Keys: []security.JwKey{jwKey},
	})
	jwKey.Id = "K1"
	jwksBody, _ = json.Marshal(&security.JwKeys{
		Keys: []security.JwKey{jwKey},
	})
}

type mockedHandler struct {
	counter  int
	status   int
	mimeType string
	body     []byte
	f        func(http.ResponseWriter, *http.Request)
}

func (mh *mockedHandler) handler(w http.ResponseWriter, r *http.Request) {
	if mh.f != nil {
		mh.f(w, r)
	} else {
		if len(mh.mimeType) > 0 {
			w.Header().Set("Content-Type", mh.mimeType)
		}
		if mh.status == 0 {
			mh.status = http.StatusOK
		}
		w.WriteHeader(mh.status)
		if len(mh.body) > 0 {
			_, _ = w.Write(mh.body)
		}
	}
}

func (mh *mockedHandler) reset() {
	mh.counter = 0
}

type handler struct {
	counter      int
	paths        map[string]*mockedHandler
	missingPaths map[string]int
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.counter++
	if mock, found := h.paths[r.URL.Path]; found {
		mock.counter++
		mock.handler(w, r)
	} else {
		h.missingPaths[r.URL.Path]++
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *handler) reset() {
	for _, mock := range h.paths {
		mock.reset()
	}
	h.missingPaths = make(map[string]int)
	h.counter = 0
}

func (h *handler) clear() {
	h.paths = make(map[string]*mockedHandler)
	h.missingPaths = make(map[string]int)
	h.counter = 0
}

func (h *handler) hits(path string) int {
	if mock, found := h.paths[path]; found {
		return mock.counter
	}
	return h.missingPaths[path]
}

func (h *handler) requests() int {
	return h.counter
}

func (h *handler) mock(path string, mock *mockedHandler) {
	h.paths[path] = mock
}

func oidConfigBytes(issuer string) []byte {
	oidConfig, _ := json.Marshal(&security.OpenIdConfiguration{
		Issuer:                            fmt.Sprintf("https://%s", issuer),
		AuthorizationEndpoint:             fmt.Sprintf("https://%s/oauth/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("https://%s/oauth/token", issuer),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256", "HS256"},
		UserinfoEndpoint:                    fmt.Sprintf("https://%s/user_info", issuer),
		JwksUri:                             fmt.Sprintf("https://%s/jwks", issuer),
		EndSessionEndpoint:                  fmt.Sprintf("https://%s/logout", issuer),
		ScopesSupported:                     []string{"openid", "roles"},
		ResponseTypesSupported:              []string{"code", "token"},
		SubjectTypesSupported:               []string{"public"},
		IdTokenSigningAlgValuesSupported:    []string{"RS256", "HS256"},
		IdTokenEncryptionAlgValuesSupported: []string{"none"},
		ClaimTypesSupported:                 []string{"normal"},
		ClaimsSupported:                     []string{"username", "iss", "roles"},
		ClaimsParameterSupported:            false,
		ServiceDocumentation:                fmt.Sprintf("https://%s/doc", issuer),
		UiLocalesSupported:                  []string{"en-US"},
		CodeChallengeMethodsSupported:       []string{"plain", "S256"},
	})
	return oidConfig
}

func TestDefaultClaimsMapper(t *testing.T) {
	t.Run("Test valid claims", func(t *testing.T) {
		user, e := security.DefaultClaimsMapper(&jwt.MapClaims{
			"sub":   "username",
			"iss":   "issuer",
			"scope": "openid admin",
		})
		if e != nil {
			t.Errorf("mapping should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("mapping should return a user")
		} else if user.Username != "username" {
			t.Errorf("Unexpected username '%s'", user.Username)
		} else if user.Origin != "issuer" {
			t.Errorf("Unexpected origin '%s'", user.Origin)
		} else if len(user.Scopes) != 2 || user.Scopes[0] != "openid" || user.Scopes[1] != "admin" {
			t.Errorf("Unexpected scopes '%v'", user.Scopes)
		}
		user, e = security.DefaultClaimsMapper(&jwt.MapClaims{
			"sub": "username",
		})
		if e != nil {
			t.Errorf("mapping should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("mapping should return a user")
		} else if user.Username != "username" {
			t.Errorf("Unexpected username '%s'", user.Username)
		} else if user.Origin != "" {
			t.Errorf("Unexpected origin '%s'", user.Origin)
		} else if len(user.Scopes) != 0 {
			t.Errorf("Unexpected scopes '%v'", user.Scopes)
		}
		user, e = security.DefaultClaimsMapper(&jwt.MapClaims{
			"sub":   "username",
			"scope": []string{"openid"},
		})
		if e != nil {
			t.Errorf("mapping should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("mapping should return a user")
		} else if user.Username != "username" {
			t.Errorf("Unexpected username '%s'", user.Username)
		} else if user.Origin != "" {
			t.Errorf("Unexpected origin '%s'", user.Origin)
		} else if len(user.Scopes) != 1 || user.Scopes[0] != "openid" {
			t.Errorf("Unexpected scopes '%v'", user.Scopes)
		}
	})
	t.Run("Test invalid claims", func(t *testing.T) {
		user, e := security.DefaultClaimsMapper(nil)
		if !security.InvalidClainsError.IsKindOf(e) {
			t.Errorf("mapping should fail with invalid claims error : %v", e)
		} else if user != nil {
			t.Error("mapping should not return a user with no claims")
		}
		user, e = security.DefaultClaimsMapper(&jwt.MapClaims{
			"iss":   "issuer",
			"scope": "openid admin",
		})
		if !security.InvalidClainsError.IsKindOf(e) {
			t.Errorf("mapping should fail with invalid claims error : %v", e)
		} else if user != nil {
			t.Error("mapping should not return a user with no claims")
		}
		user, e = security.DefaultClaimsMapper(&jwt.MapClaims{
			"sub":   true,
			"iss":   "issuer",
			"scope": "openid admin",
		})
		if !security.InvalidClainsError.IsKindOf(e) {
			t.Errorf("mapping should fail with invalid claims error : %v", e)
		} else if user != nil {
			t.Error("mapping should not return a user with no claims")
		}
		user, e = security.DefaultClaimsMapper(&jwt.MapClaims{
			"sub":   "username",
			"iss":   true,
			"scope": "openid admin",
		})
		if !security.InvalidClainsError.IsKindOf(e) {
			t.Errorf("mapping should fail with invalid claims error : %v", e)
		} else if user != nil {
			t.Error("mapping should not return a user with no claims")
		}
		user, e = security.DefaultClaimsMapper(&jwt.MapClaims{
			"sub":   "username",
			"iss":   "issuer",
			"scope": true,
		})
		if !security.InvalidClainsError.IsKindOf(e) {
			t.Errorf("mapping should fail with invalid claims error : %v", e)
		} else if user != nil {
			t.Error("mapping should not return a user with no claims")
		}
	})
}

func TestOpenIdIdentityProviderBuilder(t *testing.T) {
	h := &handler{}
	h.clear()
	server := httptest.NewTLSServer(h)
	defer server.Close()

	oidConfig := oidConfigBytes(server.Listener.Addr().String())

	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs, _ = x509.SystemCertPool()
	tlsConfig.RootCAs.AddCert(server.Certificate())

	t.Run("Test Invalid open id server url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id provider with an invalid url should fail")
			}
		}()
		security.OpenIdIdentityProvider("invalid url")
	})
	t.Run("Test non-existing open id url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id provider with no endpoints should fail")
			}
		}()
		security.OpenIdIdentityProvider("https://localhost:23943").Tls(tlsConfig).
			OpenIdConfigurationEndpoint("somehing").Build().TokenIntrospector()
	})
	t.Run("Test no endpoints provided", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id provider with no endpoints should fail")
			} else if h.hits("/.well-known/openid-configuration") == 0 {
				t.Errorf("When giving no specific endpoints the well-known endpoint should be called")
			}
		}()
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).Build().TokenIntrospector()
	})
	h.reset()
	t.Run("Test invalid openid configuration url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id provider with no endpoints should fail")
			} else if h.requests() > 0 {
				t.Errorf("no calls shoult have been made at all")
			}
		}()
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			OpenIdConfigurationEndpoint("%4k").Build()
	})
	h.reset()
	t.Run("Test invalid provided openid configuration url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id with a faulty non-default endpoint should fail")
			} else if h.hits("/openid-configuration") == 0 {
				t.Errorf("calls shoult have been made to the provided endpoint")
			}
		}()
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			OpenIdConfigurationEndpoint("openid-configuration").Build()
	})
	h.reset()
	t.Run("Test invalid openid configuration content", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id with invalid content should fail")
			} else if h.hits("/openid-configuration") == 0 {
				t.Errorf("calls should not have been made to the provided endpoint")
			}
		}()
		h.mock("/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: []byte("invalid json")})
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			OpenIdConfigurationEndpoint("openid-configuration").Build()
	})
	h.reset()
	t.Run("Test invalid claims mapper", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Creating an open id with a nil claims mapper should fail")
			} else if h.requests() != 0 {
				t.Errorf("calls should not have been made to the openid server")
			}
		}()
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			OpenIdConfigurationEndpoint("openid-configuration").ClaimsMapper(nil).Build()
	})
	h.reset()
	t.Run("Test invalid token endpoint", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("An invalid token endpoint should fail")
			} else if h.requests() != 1 {
				t.Errorf("only the openid configuration should have been attempted")
			}
		}()
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			TokenEndpoint("%2k").Build()
	})
	h.reset()
	t.Run("Test invalid introspection endpoint", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("An invalid introspection endpoint should fail")
			} else if h.requests() != 1 {
				t.Errorf("only the openid configuration should have been attempted")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			IntrospectionEndpoint("%2k").Build()
	})
	h.reset()
	t.Run("Test missing client credentials with invalid jwks url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("An invalid token endpoint should fail")
			} else if h.requests() != 2 || h.hits("/.well-known/openid-configuration") != 1 || h.hits("/jwks") != 1 {
				t.Errorf("expected to have called the openid configuration and the jwks endpoint")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).Build().TokenIntrospector()
	})
	h.reset()
	t.Run("Test possible introspection with explicit invalid jwks endpoint", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("An invalid token endpoint should fail")
			} else if h.requests() != 1 && h.hits("/.well-known/openid-configuration") != 1 {
				t.Errorf("expected to have called only the openid configuration")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).Tls(tlsConfig).
			Client("user", "password").JwksEndpoint("%2k").Build()
	})
	h.reset()
	t.Run("Test possible introspection with invalid jwks endpoint", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("At least introspection is possible, should not fail")
			} else if h.requests() != 3 || h.hits("/.well-known/openid-configuration") != 1 || h.hits("/oauth/token") != 1 || h.hits("/jwks") != 1 {
				t.Errorf("expected to have called the openid configuration, token and the jwks endpoint")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()+"/").Tls(tlsConfig).
			Client("user", "password").Build()
	})
	h.reset()
	t.Run("Test possible introspection with invalid jwks keys", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Keys are not valid, should fail")
			} else if h.requests() != 1 || h.hits("/.well-known/openid-configuration") != 1 {
				t.Errorf("expected to have called only the openid configuration")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).Tls(tlsConfig).
			Client("user", "password").
			Jwks([]security.JwKey{{
				Id:        "something",
				Algorithm: "OTHER",
			}}).Build()
	})
	h.reset()
	t.Run("Test possible introspection with invalid jwks key modulus", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Keys are not valid, should fail")
			} else if h.requests() != 1 || h.hits("/.well-known/openid-configuration") != 1 {
				t.Errorf("expected to have called only the openid configuration")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		key := jwKey
		key.Modulus = key.Modulus + "="
		security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).Tls(tlsConfig).
			Client("user", "password").
			Jwks([]security.JwKey{key}).Build()
	})
	h.reset()
	t.Run("Test possible introspection with invalid jwks key exponent", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Keys are not valid, should fail")
			} else if h.requests() != 1 || h.hits("/.well-known/openid-configuration") != 1 {
				t.Errorf("expected to have called only the openid configuration")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		key := jwKey
		key.Exponent = key.Exponent + "="
		security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).Tls(tlsConfig).
			Client("user", "password").
			Jwks([]security.JwKey{key}).Build()
	})
	h.reset()
	t.Run("Test possible introspection with empty jwks keys", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Keys are not valid, should fail")
			} else if h.requests() != 0 {
				t.Errorf("should have failed while setting")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).Tls(tlsConfig).
			Client("user", "password").
			Jwks(nil).Build()
	})
	h.clear()
	t.Run("Test invalid introspection with failing jwks url", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("jwks not providing keys, should fail")
			} else if h.requests() != 2 || h.hits("/.well-known/openid-configuration") != 1 || h.hits("/jwks") != 1 {
				t.Errorf("should have called openid configuration and jwks endpoints")
			}
		}()
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).
			JwksEndpoint("jwks").Build().TokenIntrospector()
	})
	h.reset()
	t.Run("Test invalid introspection with valid jwks url", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("jwks provides keys, should not fail")
			} else if h.requests() != 2 || h.hits("/.well-known/openid-configuration") != 1 || h.hits("/jwks") != 1 {
				t.Errorf("should have called openid configuration and jwks endpoints")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/jwks", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: jwksBody})
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).Build()
	})
	h.reset()
	t.Run("Test invalid introspection with invalid jwks keys", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("invalid jws keys, should fail")
			} else if h.requests() != 2 || h.hits("/.well-known/openid-configuration") != 1 || h.hits("/jwks") != 1 {
				t.Errorf("should have called openid configuration and jwks endpoints")
			}
		}()
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/jwks", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: []byte("wrong")})
		security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).Tls(tlsConfig).Build().TokenIntrospector()
	})
	h.reset()
}

func TestOauth2IdentityProvider_TokenIntrospector(t *testing.T) {
	h := &handler{}
	h.clear()
	server := httptest.NewTLSServer(h)
	server.Certificate()
	defer server.Close()

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   "username",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"nbf":   time.Now().Add(-time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid",
		"jti":   0,
		"iss":   fmt.Sprintf("https://%s", server.Listener.Addr().String()),
	})
	jwtToken.Header["kid"] = "K1"
	token, _ := jwtToken.SignedString(prvKey)

	oidConfig := oidConfigBytes(server.Listener.Addr().String())

	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs, _ = x509.SystemCertPool()
	tlsConfig.RootCAs.AddCert(server.Certificate())

	t.Run("Test successful jwt validation", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		h.mock("/jwks", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: jwksBody})
		provider := security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).
			Tls(tlsConfig).
			Build().TokenIntrospector()
		if user, e := provider.Introspect(token); e != nil {
			t.Errorf("introspection should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("introspection should return a user")
		} else if user.Username != "username" {
			t.Errorf("Unexpected token username '%s'", user.Username)
		}
	})
	h.clear()
	t.Run("Test successful jwt validation with key refresh", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		body := oldJwksBody
		h.mock("/jwks", &mockedHandler{f: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			body = jwksBody
		}})
		provider := security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).
			Tls(tlsConfig).
			Build().TokenIntrospector()
		if user, e := provider.Introspect(token); e != nil {
			t.Errorf("introspection should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("introspection should return a user")
		} else if user.Username != "username" {
			t.Errorf("Unexpected token username '%s'", user.Username)
		}
	})
	h.clear()
	t.Run("Test unsuccessful jwt validation with unknown key", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		h.mock("/jwks", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oldJwksBody})
		provider := security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).
			Tls(tlsConfig).
			Build().TokenIntrospector()
		if user, e := provider.Introspect(token); e == nil {
			t.Errorf("introspection should fail with an unknown signing key")
		} else if user != nil {
			t.Error("introspection should not return a user")
		}
	})
	h.clear()
	t.Run("Test successful jwt validation with provided jwks", func(t *testing.T) {
		provider := security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).
			Tls(tlsConfig).Jwks([]security.JwKey{jwKey}).
			Build().TokenIntrospector()
		if user, e := provider.Introspect(token); e != nil {
			t.Errorf("introspection should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("introspection should return a user")
		} else if user.Username != "username" {
			t.Errorf("Unexpected token username '%s'", user.Username)
		}
	})
	h.clear()
	t.Run("Test unsuccessful jwt validation with bad signature", func(t *testing.T) {
		provider := security.OpenIdIdentityProvider("https://" + server.Listener.Addr().String()).
			Tls(tlsConfig).Jwks([]security.JwKey{jwKey}).
			Build().TokenIntrospector()
		if user, e := provider.Introspect(token + "="); e == nil {
			t.Error("introspection should fail with an invalid signature")
		} else if user != nil {
			t.Error("introspection should not return a user")
		}
	})
	h.clear()
	t.Run("Test successful jwt token introspection", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		provider := security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).
			Tls(tlsConfig).Client("client", "secret").
			Build().TokenIntrospector()

		introspection, _ := json.Marshal(&security.TokenIntrospection{
			Active:     true,
			Scope:      "openid",
			ClientId:   "client",
			Username:   "user1",
			Type:       "bearer",
			Expiration: time.Now().Add(time.Hour).Unix(),
			Issued:     time.Now().Unix(),
			Starting:   time.Now().Add(-time.Hour).Unix(),
			Subject:    "user1",
			Audience:   "public",
			Issuer:     "https://" + server.Listener.Addr().String(),
			TokenId:    "124123",
		})
		h.mock("/introspect", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: introspection})
		if user, e := provider.Introspect(token); e != nil {
			t.Errorf("introspection should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("introspection should return a user")
		} else if user.Username != "user1" {
			t.Errorf("Unexpected token username '%s'", user.Username)
		} else if len(user.Scopes) != 1 || user.Scopes[0] != "openid" {
			t.Errorf("Unexpected token scopes '%v'", user.Scopes)
		}
	})
	h.reset()
	t.Run("Test successful opaque token introspection", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		provider := security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).
			Tls(tlsConfig).Client("client", "secret").Jwks([]security.JwKey{jwKey}).
			Build().TokenIntrospector()
		introspection, _ := json.Marshal(&security.TokenIntrospection{
			Active:     true,
			Scope:      "openid",
			ClientId:   "client",
			Username:   "user1",
			Type:       "bearer",
			Expiration: time.Now().Add(time.Hour).Unix(),
			Issued:     time.Now().Unix(),
			Starting:   time.Now().Add(-time.Hour).Unix(),
			Subject:    "user1",
			Audience:   "public",
			Issuer:     "https://" + server.Listener.Addr().String(),
			TokenId:    "124123",
		})
		h.mock("/introspect", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: introspection})
		if user, e := provider.Introspect("something"); e != nil {
			t.Errorf("introspection should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("introspection should return a user")
		} else if user.Username != "user1" {
			t.Errorf("Unexpected token username '%s'", user.Username)
		} else if len(user.Scopes) != 1 || user.Scopes[0] != "openid" {
			t.Errorf("Unexpected token scopes '%v'", user.Scopes)
		}
	})
	h.clear()
	t.Run("Test token introspection with invalid endpoint", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		provider := security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).
			Tls(tlsConfig).Client("client", "secret").
			Build().TokenIntrospector()
		if user, e := provider.Introspect("something"); e == nil {
			t.Error("introspection should fail with an inactive token")
		} else if user != nil {
			t.Error("introspection should not return a user")
		}
	})
	h.reset()
	t.Run("Test token introspection wth invalid response", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		provider := security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).
			Tls(tlsConfig).Client("client", "secret").
			Build().TokenIntrospector()
		h.mock("/introspect", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: []byte("invalid json")})
		if user, e := provider.Introspect("something"); e == nil {
			t.Error("introspection should fail with an inactive token")
		} else if user != nil {
			t.Error("introspection should not return a user")
		}
	})
	h.reset()
	t.Run("Test inactive token introspection", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		provider := security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).
			Tls(tlsConfig).Client("client", "secret").
			Build().TokenIntrospector()
		introspection, _ := json.Marshal(&security.TokenIntrospection{
			Active:     false,
			Scope:      "openid",
			ClientId:   "client",
			Username:   "user1",
			Type:       "bearer",
			Expiration: time.Now().Add(time.Hour).Unix(),
			Issued:     time.Now().Unix(),
			Starting:   time.Now().Add(-time.Hour).Unix(),
			Subject:    "user1",
			Audience:   "public",
			Issuer:     "https://" + server.Listener.Addr().String(),
			TokenId:    "124123",
		})
		h.mock("/introspect", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: introspection})
		if user, e := provider.Introspect("something"); e == nil {
			t.Error("introspection should fail with an inactive token")
		} else if user != nil {
			t.Error("introspection should not return a user")
		}
	})
	h.clear()
	t.Run("Test successful jwt fallback token introspection", func(t *testing.T) {
		h.mock("/.well-known/openid-configuration", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oidConfig})
		h.mock("/oauth/token", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: tokenResponse})
		h.mock("/jwks", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: oldJwksBody})
		provider := security.OpenIdIdentityProvider("https://"+server.Listener.Addr().String()).
			Tls(tlsConfig).Client("client", "secret").ClaimsMapper(security.DefaultClaimsMapper).
			JwtValidationFallback(true).
			Build().TokenIntrospector()

		introspection, _ := json.Marshal(&security.TokenIntrospection{
			Active:     true,
			Scope:      []string{"openid"},
			ClientId:   "client",
			Username:   "user1",
			Type:       "bearer",
			Expiration: time.Now().Add(time.Hour).Unix(),
			Issued:     time.Now().Unix(),
			Starting:   time.Now().Add(-time.Hour).Unix(),
			Subject:    "user1",
			Audience:   "public",
			Issuer:     "https://" + server.Listener.Addr().String(),
			TokenId:    "124123",
		})
		h.mock("/introspect", &mockedHandler{status: http.StatusOK, mimeType: "application/json", body: introspection})
		if user, e := provider.Introspect(token); e != nil {
			t.Errorf("introspection should not fail with a valid token: %v", e)
		} else if user == nil {
			t.Error("introspection should return a user")
		} else if user.Username != "user1" {
			t.Errorf("Unexpected token username '%s'", user.Username)
		} else if len(user.Scopes) != 1 || user.Scopes[0] != "openid" {
			t.Errorf("Unexpected token scopes '%v'", user.Scopes)
		}
	})
}
