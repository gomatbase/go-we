// Copyright 2025 GOM. All rights reserved.
// Since 13/01/2025 By GOM
// Licensed under MIT License

package security_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/security"
	"github.com/gomatbase/go-we/test"
)

func createTestCA(parent *x509.Certificate, parentPk *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "testCA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	pk, _ := rsa.GenerateKey(rand.Reader, 2048)

	if parent == nil {
		parent = template
		parentPk = pk
	}

	bytes, e := x509.CreateCertificate(rand.Reader, template, parent, &pk.PublicKey, parentPk)
	if e != nil {
		panic(e)
	}

	if ca, e := x509.ParseCertificate(bytes); e != nil {
		panic(e)
	} else {
		return ca, pk
	}
}

func clientCertificate(cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	pk, e := rsa.GenerateKey(rand.Reader, 2048)

	bytes, e := x509.CreateCertificate(rand.Reader, template, ca, &pk.PublicKey, caKey)
	if e != nil {
		panic(e)
	}

	if cert, e := x509.ParseCertificate(bytes); e != nil {
		panic(e)
	} else {
		return cert, pk
	}
}

func TestReverseProxyMtlsFilter(t *testing.T) {
	// create a test CA pool
	ca, caPk := createTestCA(nil, nil)
	clientCert, _ := clientCertificate("testClient", ca, caPk)
	clientBase64 := base64.StdEncoding.EncodeToString(clientCert.Raw)

	t.Run("Test no forwarded client certificate", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS != nil {
			t.Errorf("Expected request TLS connection state to be nil")
		}
	})
	t.Run("Test simple forwarded client certificate", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS == nil {
			t.Errorf("Expected request TLS attribute to be set")
		} else if len(scope.Request().TLS.PeerCertificates) != 1 {
			t.Errorf("Expected the client certificate to be added to the peer certificates")
		} else if scope.Request().TLS.PeerCertificates[0].Subject.CommonName != "testClient" {
			t.Errorf("Expected the client certificate to have \"testClient\" as common name: %s", scope.Request().TLS.PeerCertificates[0].Subject.CommonName)
		}
	})
	t.Run("Test forwarded client certificate with custom function", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).WithDecodingFunction(func(s string) ([]*x509.Certificate, error) {
			return security.PlainHeaderCertDecoding(s[1:])
		}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set(security.DefaultCertHeader, "."+clientBase64)
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS == nil {
			t.Errorf("Expected request TLS attribute to be set")
		} else if len(scope.Request().TLS.PeerCertificates) != 1 {
			t.Errorf("Expected the client certificate to be added to the peer certificates")
		} else if scope.Request().TLS.PeerCertificates[0].Subject.CommonName != "testClient" {
			t.Errorf("Expected the client certificate to have \"testClient\" as common name: %s", scope.Request().TLS.PeerCertificates[0].Subject.CommonName)
		}
	})
	t.Run("Test forwarded client certificate on custom header", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).WithClientCertHeader("x-test").Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set("x-test", clientBase64)
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS == nil {
			t.Errorf("Expected request TLS attribute to be set")
		} else if len(scope.Request().TLS.PeerCertificates) != 1 {
			t.Errorf("Expected the client certificate to be added to the peer certificates")
		} else if scope.Request().TLS.PeerCertificates[0].Subject.CommonName != "testClient" {
			t.Errorf("Expected the client certificate to have \"testClient\" as common name: %s", scope.Request().TLS.PeerCertificates[0].Subject.CommonName)
		}
	})
	t.Run("Test simple forwarded client certificate with PEM cas", func(t *testing.T) {
		certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
		filter := security.ReverseProxyMtlsFilter().AcceptingPEMCAs([]string{string(certBytes)}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS == nil {
			t.Errorf("Expected request TLS attribute to be set")
		} else if len(scope.Request().TLS.PeerCertificates) != 1 {
			t.Errorf("Expected the client certificate to be added to the peer certificates")
		} else if scope.Request().TLS.PeerCertificates[0].Subject.CommonName != "testClient" {
			t.Errorf("Expected the client certificate to have \"testClient\" as common name: %s", scope.Request().TLS.PeerCertificates[0].Subject.CommonName)
		}
	})
	t.Run("Test filter build with invalid PEM cas", func(t *testing.T) {
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()
			security.ReverseProxyMtlsFilter().AcceptingPEMCAs([]string{"something"}).Build()
		}()

		if !panicked {
			t.Errorf("Expected a panic when building the filter with an invalid PEM CA")
		}

		panicked = false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()

			security.ReverseProxyMtlsFilter().AcceptingPEMCAs([]string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}))}).Build()
		}()

		if !panicked {
			t.Errorf("Expected a panic when building the filter with an invalid PEM CA")
		}
	})
	t.Run("Test forwarded client certificate on TLS", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		scope.Request().TLS = &tls.ConnectionState{}
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS == nil {
			t.Errorf("Expected request TLS attribute to be set")
		} else if len(scope.Request().TLS.PeerCertificates) != 0 {
			t.Errorf("Expected the client certificate not to be added to the peer certificates")
		}
	})
	t.Run("Test forwarded client certificate on TLS with dual support", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).WithDualSupport().Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		connectionState := &tls.ConnectionState{}
		scope.Request().TLS = connectionState
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS != connectionState {
			t.Errorf("Expected request TLS attribute to be the original object")
		} else if len(scope.Request().TLS.PeerCertificates) != 1 {
			t.Errorf("Expected the client certificate to be added to the peer certificates")
		} else if scope.Request().TLS.PeerCertificates[0].Subject.CommonName != "testClient" {
			t.Errorf("Expected the client certificate to have \"testClient\" as common name: %s", scope.Request().TLS.PeerCertificates[0].Subject.CommonName)
		}
	})
	t.Run("Test invalid forwarded client certificate", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")

		scope.Request().Header.Set(security.DefaultCertHeader, "")
		e := filter.Filter(nil, scope)
		if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected an unauthorized error to be raised with an empty header: %v", e)
		}

		scope.Request().Header.Set(security.DefaultCertHeader, "invalid")
		e = filter.Filter(nil, scope)
		if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected an unauthorized error to be raised with an invalid base64 header: %v", e)
		}

		scope.Request().Header.Set(security.DefaultCertHeader, base64.StdEncoding.EncodeToString([]byte("invalid")))
		e = filter.Filter(nil, scope)
		if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected an unauthorized error to be raised with an invalid cert header: %v", e)
		}

	})
	t.Run("Test invalid forwarded client certificate ignoring validation errors", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).IgnoringValidationErrors().Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")

		scope.Request().Header.Set(security.DefaultCertHeader, "")
		e := filter.Filter(nil, scope)
		if e != nil {
			t.Errorf("Unexpected error raised with an empty header: %v", e)
		}

		scope.Request().Header.Set(security.DefaultCertHeader, "invalid")
		e = filter.Filter(nil, scope)
		if e != nil {
			t.Errorf("Unexpected error raised with an invalid base64 header: %v", e)
		}

		scope.Request().Header.Set(security.DefaultCertHeader, base64.StdEncoding.EncodeToString([]byte("invalid")))
		e = filter.Filter(nil, scope)
		if e != nil {
			t.Errorf("Unexpected error raised with invalid cert header: %v", e)
		}

	})
	t.Run("Test unverifiable forwarded client certificate", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")

		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		e := filter.Filter(nil, scope)
		if !events.UnauthorizedError.Is(e) {
			t.Errorf("Expected an unauthorized error to be raised with an empty header: %v", e)
		}
	})
	t.Run("Test unverifiable forwarded client certificate ignoring verification errors", func(t *testing.T) {
		filter := security.ReverseProxyMtlsFilter().IgnoringVerificationErrors().Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")

		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		e := filter.Filter(nil, scope)
		if e != nil {
			t.Errorf("Unexpected error with an unverifiable certificate: %v", e)
		}
		if scope.Request().TLS != nil {
			t.Errorf("Expected request TLS connection state to be nil")
		}
	})
	t.Run("Test forwarded client certificate with intermediate", func(t *testing.T) {
		intermediate, intermediatePk := createTestCA(ca, caPk)
		clientCert, _ := clientCertificate("testClientWithIntermediate", intermediate, intermediatePk)
		clientBase64 := fmt.Sprintf("%s,%s", base64.StdEncoding.EncodeToString(clientCert.Raw), base64.StdEncoding.EncodeToString(intermediate.Raw))

		filter := security.ReverseProxyMtlsFilter().AcceptingCAs([]*x509.Certificate{ca}).Build()
		scope := test.MockedRequestScope("GET", "https://localhost:8080")
		scope.Request().Header.Set(security.DefaultCertHeader, clientBase64)
		e := filter.Filter(nil, scope)

		if e != nil {
			t.Errorf("Expected no error, got %v", e)
		} else if scope.Request().TLS == nil {
			t.Errorf("Expected request TLS attribute to be set")
		} else if len(scope.Request().TLS.PeerCertificates) != 2 {
			t.Errorf("Expected the client certificate to be added to the peer certificates")
		} else if scope.Request().TLS.PeerCertificates[0].Subject.CommonName != "testClientWithIntermediate" {
			t.Errorf("Expected the client certificate to have \"testClientWithIntermediate\" as common name: %s", scope.Request().TLS.PeerCertificates[0].Subject.CommonName)
		}
	})
}
