// Copyright 2025 GOM. All rights reserved.
// Since 30/01/2025 By GOM
// Licensed under MIT License

package security_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

func TestDefaultCertificateIdExtractor(t *testing.T) {
	t.Run("Test nil certificate", func(t *testing.T) {
		// this situation should never actually occur
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic during nil certificate extraction")
			}
		}()
		extractor := security.DefaultCertificateIdExtractor
		_, _ = extractor(nil)
	})

	t.Run("Test with certificate", func(t *testing.T) {
		ca, caPk := createTestCA(nil, nil)
		clientCert, _ := clientCertificate("testClient", ca, caPk)
		clientCert.Subject.OrganizationalUnit = []string{"test", "client"}

		extractor := security.DefaultCertificateIdExtractor
		if user, e := extractor(clientCert); e != nil {
			t.Error("unexpected error during extraction", e)
		} else if user == nil {
			t.Error("expected user when extracting from a valid certificate")
		} else {
			if user.Username != clientCert.Subject.CommonName {
				t.Error("unexpected username extracted from certificate", user)
			}
			if len(user.Scopes) != 2 {
				t.Error("expected scopes extracted from certificate", user)
			} else if user.Scopes[0] != "test" || user.Scopes[1] != "client" {
				t.Error("unexpected scopes extracted from certificate", user)
			}
			if user.Origin != security.DefaultMtlsRealm {
				t.Error("unexpected origin extracted from certificate", user)
			}
			if user.OriginId != clientCert.Subject.CommonName {
				t.Error("unexpected origin id extracted from certificate", user)
			}
			if !user.Active {
				t.Error("expected user status to be active", user)
			}
		}
	})
}

func TestMtlsAuthenticationProvider(t *testing.T) {
	ca, caPk := createTestCA(nil, nil)
	clientCert, _ := clientCertificate("testClient", ca, caPk)

	t.Run("Test default builder", func(t *testing.T) {
		provider := security.MtlsAuthenticationProvider().Build()
		if provider.Realm() != security.DefaultMtlsRealm {
			t.Errorf("realm should be %s, instead it's : %s", security.DefaultMtlsRealm, provider.Realm())
		}
		if provider.IsValid(nil) || provider.IsValid(&security.User{}) {
			t.Error("mtls provider should never validate existing users")
		}
		if provider.Challenge() != "" {
			t.Error("mtls provider should have no challenge")
		}
		if provider.Endpoints() != nil {
			t.Error("mtls provider should have no custom endpoints")
		}
		scope := test.MockedRequestScope("GET", "/")
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Error("unexpected error during non-mtls authentication", e)
		} else if user != nil {
			t.Error("unexpected user for non-mtls authentication", user)
		}

		scope.Request().TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Error("unexpected error during mtls authentication", e)
		} else if user == nil {
			t.Error("expected user during mtls")
		} else if user.Username != clientCert.Subject.CommonName {
			t.Error("unexpected username extracted from mtls certificate", user)
		}
	})
	t.Run("Test configured builder", func(t *testing.T) {
		called := false
		provider := security.MtlsAuthenticationProvider().
			Realm("test").WithCertificateIdExtractor(func(certificate *x509.Certificate) (*security.User, error) {
			called = true
			return &security.User{Username: "test user"}, nil
		}).Build()
		if provider.Realm() != "test" {
			t.Errorf("realm should be test, instead it's : %s", provider.Realm())
		}
		if provider.IsValid(nil) || provider.IsValid(&security.User{}) {
			t.Error("mtls provider should never validate existing users")
		}
		if provider.Challenge() != "" {
			t.Error("mtls provider should have no challenge")
		}
		if provider.Endpoints() != nil {
			t.Error("mtls provider should have no custom endpoints")
		}
		scope := test.MockedRequestScope("GET", "/")
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Error("unexpected error during non-mtls authentication", e)
		} else if user != nil {
			t.Error("unexpected user for non-mtls authentication", user)
		} else if called {
			t.Error("extractor id should never be called for non-mtls authentication")
		}

		scope.Request().TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		if user, e := provider.Authenticate(nil, scope); e != nil {
			t.Error("unexpected error during mtls authentication", e)
		} else if user == nil {
			t.Error("expected user during mtls")
		} else if user.Username != "test user" {
			t.Error("unexpected username extracted from mtls certificate", user)
		}
	})
	t.Run("Test extractor id with error", func(t *testing.T) {
		provider := security.MtlsAuthenticationProvider().
			WithCertificateIdExtractor(func(certificate *x509.Certificate) (*security.User, error) {
				return &security.User{Username: "test user"}, events.UnauthorizedError
			}).Build()
		scope := test.MockedRequestScope("GET", "/")
		scope.Request().TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		if user, e := provider.Authenticate(nil, scope); !events.UnauthorizedError.Is(e) {
			t.Error("expected unauthorized error", e)
		} else if user == nil {
			t.Error("expected user during mtls")
		} else if user.Username != "test user" {
			t.Error("unexpected username extracted from mtls certificate", user)
		}
	})
}
