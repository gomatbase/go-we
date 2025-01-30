// Copyright 2025 GOM. All rights reserved.
// Since 30/01/2025 By GOM
// Licensed under MIT License

package security

import (
	"crypto/x509"
	"net/http"

	"github.com/gomatbase/go-we"
)

const (
	// DefaultMtlsRealm is the default realm for an MTLS authentication provider.
	DefaultMtlsRealm = "mtls"
)

// CertificateIdExtractor is a type of function that extracts a user from a leaf certificate.
type CertificateIdExtractor func(certificate *x509.Certificate) (*User, error)

// DefaultCertificateIdExtractor is a default implementation of CertificateIdExtractor.
// The default certificate id extractor simply uses the common name as both the username and the origin id, and adds
// all defined organizational units as user scopes. It assumes a proper MTLS handshake and as such, it will only be
// called when a successful handshake has been completed resulting in a valid client certificate. No authentication
// errors are returned since Mtls authentication failure would fail at the handshake step. The default function
// is meant mainly for testing a quick startup projects, in most real life cases a custom implementation would be provided.
func DefaultCertificateIdExtractor(certificate *x509.Certificate) (*User, error) {
	return &User{
		Username: certificate.Subject.CommonName,
		Scopes:   certificate.Subject.OrganizationalUnit,
		Origin:   DefaultMtlsRealm,
		OriginId: certificate.Subject.CommonName,
		Active:   true,
	}, nil
}

// mtlsAuthenticationProvider is an implementation of AuthenticationProvider that authenticates users based on the client certificate.
type mtlsAuthenticationProvider struct {
	realm                  string
	certificateIdExtractor CertificateIdExtractor
}

// Authenticate authenticates a user based on the client certificate in the request. If an invalid client certificate
// is provided, the tls handshake should have already failed. Making a client certificate mandatory or not is delegated
// to the tls termination configuration, and if no client certificate is present in the request, the provider
// simply returns no user and no error (effectively making the access anonymous). If authentication failure is expected
// to occur because, for example, there is no user associated to the provided certificate, the certificateIdExtractor
// function should be returning an error.
func (mtlsap *mtlsAuthenticationProvider) Authenticate(_ http.Header, scope we.RequestScope) (*User, error) {
	request := scope.Request()

	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return nil, nil
	}

	certificate := request.TLS.PeerCertificates[0]
	return mtlsap.certificateIdExtractor(certificate)
}

// Realm returns the realm of the authentication provider.
func (mtlsap *mtlsAuthenticationProvider) Realm() string {
	return mtlsap.realm
}

// IsValid always returns false for an MTLS authentication provider since the authentication is based on the client certificate.
func (mtlsap *mtlsAuthenticationProvider) IsValid(user *User) bool {
	return false
}

// Challenge returns no challenge for mtls authentication
func (mtlsap *mtlsAuthenticationProvider) Challenge() string {
	return ""
}

// Endpoints returns no custom handled endpoints for mtls authentication
func (mtlsap *mtlsAuthenticationProvider) Endpoints() []string {
	return nil
}

// MtlsAuthenticationProviderBuilder is a builder for an MTLS authentication provider.
type MtlsAuthenticationProviderBuilder interface {
	// WithCertificateIdExtractor sets the certificate id extractor for the MTLS authentication provider.
	WithCertificateIdExtractor(certificateIdExtractor CertificateIdExtractor) MtlsAuthenticationProviderBuilder
	// Realm sets the realm for the MTLS authentication provider.
	Realm(string) MtlsAuthenticationProviderBuilder
	// Build builds the MTLS authentication provider.
	Build() AuthenticationProvider
}

// mtlsAutenticationProviderBuilder is an implementation of MtlsAuthenticationProviderBuilder.
type mtlsAutenticationProviderBuilder struct {
	provider *mtlsAuthenticationProvider
}

// Realm sets the realm for the MTLS authentication provider.
func (mapb *mtlsAutenticationProviderBuilder) Realm(realm string) MtlsAuthenticationProviderBuilder {
	mapb.provider.realm = realm
	return mapb
}

// WithCertificateIdExtractor sets the certificate id extractor for the MTLS authentication provider.
func (mapb *mtlsAutenticationProviderBuilder) WithCertificateIdExtractor(certificateIdExtractor CertificateIdExtractor) MtlsAuthenticationProviderBuilder {
	mapb.provider.certificateIdExtractor = certificateIdExtractor
	return mapb
}

// Build validates the mtl authentication provider configuration, using default values for unset attributes.
func (mapb *mtlsAutenticationProviderBuilder) Build() AuthenticationProvider {
	if mapb.provider.certificateIdExtractor == nil {
		mapb.provider.certificateIdExtractor = DefaultCertificateIdExtractor
	}

	if mapb.provider.realm == "" {
		mapb.provider.realm = DefaultMtlsRealm
	}

	return mapb.provider
}

// MtlsAuthenticationProvider creates a new builder for an MTLS authentication provider.
func MtlsAuthenticationProvider() MtlsAuthenticationProviderBuilder {
	return &mtlsAutenticationProviderBuilder{provider: &mtlsAuthenticationProvider{}}
}
