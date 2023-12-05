// Copyright 2023 GOM. All rights reserved.
// Since 13/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/errors"
)

type BasicAuthenticationProviderBuilder interface {
	Realm(string) BasicAuthenticationProviderBuilder
	CredentialsProvider(CredentialsProvider) BasicAuthenticationProviderBuilder
	Build() AuthenticationProvider
}

func BasicAuthenticationProvider(users ...User) BasicAuthenticationProviderBuilder {
	builder := &basicAuthenticationProviderBuilder{provider: &basicAuthenticationProvider{}}
	if len(users) > 0 {
		builder.provider.credentialsProvider = DefaultCredentialsProvider(users...)
	}
	return builder
}

type basicAuthenticationProvider struct {
	realm               string
	credentialsProvider CredentialsProvider
}

func (bap *basicAuthenticationProvider) Authenticate(headers http.Header, scope we.RequestScope) (*User, error) {
	if authorization := scope.Request().Header.Get("Authorization"); len(authorization) > 6 &&
		strings.HasPrefix(strings.ToLower(authorization[:6]), "basic ") {

		if decoded, e := base64.StdEncoding.DecodeString(authorization[6:]); e != nil {
			return nil, errors.BadRequestError.WithPayload("text/plain", e.Error())
		} else if username, password, found := strings.Cut(string(decoded), ":"); !found {
			return nil, errors.BadRequestError.WithPayload("text/plain", "invalid credentials")
		} else {
			md5Sum := md5.Sum([]byte(password))
			if user, e := bap.credentialsProvider.Authenticate(username, base64.StdEncoding.EncodeToString(md5Sum[:])); e != nil {
				return nil, errors.ForbiddenError.WithPayload("text/plain", e.Error())
			} else {
				return user, nil
			}
		}
	}
	return nil, nil
}

func (bap *basicAuthenticationProvider) Realm() string {
	return bap.realm
}

func (bap *basicAuthenticationProvider) IsValid(user *User) bool {
	if user == nil {
		return false
	}
	return bap.credentialsProvider.Get(user.Username) != nil
}

func (bap *basicAuthenticationProvider) Challenge() string {
	return "Basic"
}

func (bap *basicAuthenticationProvider) Endpoints() []string {
	return nil
}

type basicAuthenticationProviderBuilder struct {
	provider *basicAuthenticationProvider
}

func (bapb *basicAuthenticationProviderBuilder) Realm(realm string) BasicAuthenticationProviderBuilder {
	bapb.provider.realm = realm
	return bapb
}

func (bapb *basicAuthenticationProviderBuilder) CredentialsProvider(credentialsProvider CredentialsProvider) BasicAuthenticationProviderBuilder {
	bapb.provider.credentialsProvider = credentialsProvider
	return bapb
}

func (bapb *basicAuthenticationProviderBuilder) Build() AuthenticationProvider {
	if bapb.provider.credentialsProvider == nil {
		bapb.provider.credentialsProvider = DefaultCredentialsProvider()
	}
	if len(bapb.provider.realm) == 0 {
		bapb.provider.realm = "basic"
	}
	return bapb.provider
}
