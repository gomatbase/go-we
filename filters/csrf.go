// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package filters

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	we "github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

const (
	// DefaultCsrfTokenLength is the default length of generated CSRF tokens in bytes
	DefaultCsrfTokenLength = 32
	// DefaultCsrfHeaderName is the default HTTP header name for CSRF tokens
	DefaultCsrfHeaderName = "X-CSRF-Token"
	// DefaultCsrfFieldName is the default form field name for CSRF tokens
	DefaultCsrfFieldName = "_csrf"
	// DefaultCsrfSessionKey is the default session key for storing CSRF tokens
	DefaultCsrfSessionKey = "_csrf_token"
)

// CsrfBuilder defines the builder interface for configuring CSRF protection
type CsrfBuilder interface {
	// HeaderName sets the HTTP header name for CSRF tokens (default: X-CSRF-Token)
	HeaderName(name string) CsrfBuilder
	// FieldName sets the form field name for CSRF tokens (default: _csrf)
	FieldName(name string) CsrfBuilder
	// TokenLength sets the length of generated tokens in bytes (default: 32)
	TokenLength(length int) CsrfBuilder
	// ExemptPaths adds paths that bypass CSRF validation (e.g., API endpoints with Bearer auth)
	ExemptPaths(paths ...string) CsrfBuilder
	// Build creates the configured CSRF filter
	Build() we.Filter
}

// csrf is the implementation of Csrf
type csrf struct {
	headerName  string
	fieldName   string
	tokenLength int
	exemptPaths map[string]bool
}

// Filter implements the we.Filter interface
func (c *csrf) Filter(header http.Header, scope we.RequestScope) error {
	request := scope.Request()

	// Skip CSRF validation for safe methods
	if isSafeMethod(request.Method) {
		// Generate or refresh CSRF token for safe methods
		c.ensureToken(scope)
		return nil
	}

	// Check if path is exempted
	if c.exemptPaths[request.URL.Path] {
		return nil
	}

	// Validate CSRF token for state-changing methods
	token := request.Header.Get(c.headerName)
	if token == "" {
		// Try form field as fallback
		token = request.FormValue(c.fieldName)
	}

	if token == "" {
		return events.ForbiddenError.WithPayload(
			"text/plain",
			[]byte("CSRF token missing"),
		)
	}

	// Validate token against session
	sessionToken := scope.Session().Get(DefaultCsrfSessionKey)
	if sessionToken == nil {
		return events.ForbiddenError.WithPayload(
			"text/plain",
			[]byte("CSRF validation failed"),
		)
	}

	sessionTokenStr, ok := sessionToken.(string)
	if !ok || sessionTokenStr != token {
		return events.ForbiddenError.WithPayload(
			"text/plain",
			[]byte("CSRF token invalid"),
		)
	}

	return nil
}

// ensureToken generates a new CSRF token if one doesn't exist in the session
func (c *csrf) ensureToken(scope we.RequestScope) {
	if scope.Session().Get(DefaultCsrfSessionKey) != nil {
		return
	}

	token := generateToken(c.tokenLength)
	scope.Session().Set(DefaultCsrfSessionKey, token)
}

// isSafeMethod returns true for HTTP methods that don't require CSRF validation
func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// generateToken creates a random CSRF token
func generateToken(length int) string {
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		panic("failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(token)
}

// csrfBuilder is the implementation of CsrfBuilder
type csrfBuilder struct {
	filter *csrf
}

// HeaderName sets the HTTP header name for CSRF tokens
func (cb *csrfBuilder) HeaderName(name string) CsrfBuilder {
	if name == "" {
		panic("header name cannot be empty")
	}
	cb.filter.headerName = name
	return cb
}

// FieldName sets the form field name for CSRF tokens
func (cb *csrfBuilder) FieldName(name string) CsrfBuilder {
	if name == "" {
		panic("field name cannot be empty")
	}
	cb.filter.fieldName = name
	return cb
}

// TokenLength sets the length of generated tokens
func (cb *csrfBuilder) TokenLength(length int) CsrfBuilder {
	if length <= 0 {
		panic("token length must be greater than 0")
	}
	cb.filter.tokenLength = length
	return cb
}

// ExemptPaths adds paths that bypass CSRF validation
func (cb *csrfBuilder) ExemptPaths(paths ...string) CsrfBuilder {
	if len(paths) == 0 {
		panic("at least one path must be provided")
	}
	for _, path := range paths {
		if path == "" {
			panic("path cannot be empty")
		}
		cb.filter.exemptPaths[path] = true
	}
	return cb
}

// Build creates the configured CSRF filter
func (cb *csrfBuilder) Build() we.Filter {
	return cb.filter
}

// Csrf creates a new CsrfBuilder with default configuration.
// Default configuration:
// - Header name: X-CSRF-Token
// - Field name: _csrf
// - Token length: 32 bytes
//
// Example:
//
//	filter := filters.Csrf().
//	    ExemptPaths("/api/webhook", "/health").
//	    Build()
//
//	engine := we.New().
//	    Filter(filter).
//	    Build()
func Csrf() CsrfBuilder {
	return &csrfBuilder{
		filter: &csrf{
			headerName:  DefaultCsrfHeaderName,
			fieldName:   DefaultCsrfFieldName,
			tokenLength: DefaultCsrfTokenLength,
			exemptPaths: make(map[string]bool),
		},
	}
}
