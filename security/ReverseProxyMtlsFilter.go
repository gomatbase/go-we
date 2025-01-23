// Copyright 2025 GOM. All rights reserved.
// Since 20/01/2025 By GOM
// Licensed under MIT License

package security

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strings"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

const (
	DefaultCertHeader = "X-Forwarded-Client-Cert"
)

type HeaderCertDecodingFunction func(string) ([]*x509.Certificate, error)

// PlainHeaderCertDecoding is a default decoding function for client certificates in a header. It expects the
// a base64 DER certificate string. The x-forwarded-client-cert header format has no real standard and is
// implementation specific. For other more complex implementations it may be that a specific filter is
// required and probably specific authorizations.
func PlainHeaderCertDecoding(cert string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, certString := range strings.Split(cert, ",") {
		bytes, e := base64.StdEncoding.DecodeString(certString)
		if e != nil {
			return nil, e
		}
		c, e := x509.ParseCertificate(bytes)
		if e != nil {
			return nil, e
		}
		certs = append(certs, c)
	}
	return certs, nil
}

type reverseProxyMtlsFilter struct {
	dualSupport              bool
	certHeader               string
	cas                      *x509.CertPool
	decodingFunc             HeaderCertDecodingFunction
	ignoreValidationErrors   bool
	ignoreVerificationErrors bool
}

// Filter will check if a forwarded client certificate exists in the request header and validates it if present. If
// a header is present and the validation fails, either because it contains an invalid certificate or no processable
// certificate, the filter will either return an unauthorized error or nil if configured to do so.
// If the header is not present, the filter will return nil.
// and expects the authorization rules to deny access to any endpoint requiring a client certificate.
// If the web engine is being served through tls, the filter will not check for the header by default. If the
// ReverseProxyMtlsFilter was configured to support both methods (reverse proxy headers as well as tls), it will
// still try to validate it.
func (rpmf *reverseProxyMtlsFilter) Filter(header http.Header, scope we.RequestScope) error {
	request := scope.Request()
	tlsConnectionState := request.TLS
	if request.TLS != nil {
		if !rpmf.dualSupport {
			// seems like the listener is serving on tls, no dual support, so we won't check for the header
			return nil
		}
	} else {
		tlsConnectionState = &tls.ConnectionState{
			HandshakeComplete: true,
		}
	}

	certStrings := request.Header.Values(rpmf.certHeader)
	if len(certStrings) == 0 {
		return nil
	}

	certs, e := rpmf.decodingFunc(certStrings[0])
	if e != nil || len(certs) == 0 {
		if rpmf.ignoreValidationErrors {
			return nil
		}
		return events.UnauthorizedError
	}

	var intermediates *x509.CertPool
	if len(certs) > 1 {
		// has intermediates
		intermediates = x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			intermediates.AddCert(certs[i])
		}
	}

	verifyOptions := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         rpmf.cas,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, e = certs[0].Verify(verifyOptions); e != nil {
		if rpmf.ignoreVerificationErrors {
			return nil
		}
		return events.UnauthorizedError
	}

	tlsConnectionState.PeerCertificates = append(tlsConnectionState.PeerCertificates, certs...)
	request.TLS = tlsConnectionState

	return nil
}

type ReverseProxyMtlsFilterBuilder interface {
	AcceptingCAs(certs []*x509.Certificate) ReverseProxyMtlsFilterBuilder
	AcceptingPEMCAs(certs []string) ReverseProxyMtlsFilterBuilder
	IgnoringValidationErrors() ReverseProxyMtlsFilterBuilder
	IgnoringVerificationErrors() ReverseProxyMtlsFilterBuilder
	WithDualSupport() ReverseProxyMtlsFilterBuilder
	WithClientCertHeader(header string) ReverseProxyMtlsFilterBuilder
	WithDecodingFunction(decodingFunc HeaderCertDecodingFunction) ReverseProxyMtlsFilterBuilder
	Build() we.Filter
}

type reverseProxyMtlsFilterBuilder struct {
	filter *reverseProxyMtlsFilter
}

func (rpmfb *reverseProxyMtlsFilterBuilder) IgnoringValidationErrors() ReverseProxyMtlsFilterBuilder {
	rpmfb.filter.ignoreValidationErrors = true
	return rpmfb
}

func (rpmfb *reverseProxyMtlsFilterBuilder) IgnoringVerificationErrors() ReverseProxyMtlsFilterBuilder {
	rpmfb.filter.ignoreVerificationErrors = true
	return rpmfb
}

func (rpmfb *reverseProxyMtlsFilterBuilder) WithDualSupport() ReverseProxyMtlsFilterBuilder {
	rpmfb.filter.dualSupport = true
	return rpmfb
}

func (rpmfb *reverseProxyMtlsFilterBuilder) AcceptingCAs(certs []*x509.Certificate) ReverseProxyMtlsFilterBuilder {
	rpmfb.filter.cas = x509.NewCertPool()
	for _, cert := range certs {
		rpmfb.filter.cas.AddCert(cert)
	}
	return rpmfb
}

func (rpmfb *reverseProxyMtlsFilterBuilder) AcceptingPEMCAs(certs []string) ReverseProxyMtlsFilterBuilder {
	var cas []*x509.Certificate
	for _, pemCert := range certs {
		pemBlock, _ := pem.Decode([]byte(pemCert))
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			panic(err)
		}
		cas = append(cas, cert)
	}
	return rpmfb.AcceptingCAs(cas)
}

func (rpmfb *reverseProxyMtlsFilterBuilder) WithClientCertHeader(header string) ReverseProxyMtlsFilterBuilder {
	rpmfb.filter.certHeader = header
	return rpmfb
}

func (rpmfb *reverseProxyMtlsFilterBuilder) WithDecodingFunction(decodingFunc HeaderCertDecodingFunction) ReverseProxyMtlsFilterBuilder {
	rpmfb.filter.decodingFunc = decodingFunc
	return rpmfb
}

func (rpmfb *reverseProxyMtlsFilterBuilder) Build() we.Filter {
	if rpmfb.filter.certHeader == "" {
		rpmfb.filter.certHeader = DefaultCertHeader
	}
	if rpmfb.filter.decodingFunc == nil {
		rpmfb.filter.decodingFunc = PlainHeaderCertDecoding
	}
	return rpmfb.filter
}

func ReverseProxyMtlsFilter() ReverseProxyMtlsFilterBuilder {
	return &reverseProxyMtlsFilterBuilder{filter: &reverseProxyMtlsFilter{}}
}
