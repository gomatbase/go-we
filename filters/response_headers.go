// Copyright 2026 GOM. All rights reserved.
// Since 01/04/2026 By GOM
// Licensed under MIT License

package filters

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/pathTree"
)

// FrameOption represents X-Frame-Options header values
type FrameOption string

const (
	// FrameOptionDeny prevents the page from being displayed in a frame
	FrameOptionDeny FrameOption = "DENY"

	// FrameOptionSameOrigin allows the page to be displayed in a frame on the same origin
	FrameOptionSameOrigin FrameOption = "SAMEORIGIN"
)

// FrameOptionAllowFrom creates an ALLOW-FROM directive for X-Frame-Options
// Note: ALLOW-FROM is deprecated and not supported by modern browsers
// Consider using Content-Security-Policy frame-ancestors instead
func FrameOptionAllowFrom(uri string) FrameOption {
	return FrameOption("ALLOW-FROM " + uri)
}

// ReferrerPolicyOption represents Referrer-Policy header values
type ReferrerPolicyOption string

const (
	// ReferrerPolicyNoReferrer sends no referrer information
	ReferrerPolicyNoReferrer ReferrerPolicyOption = "no-referrer"

	// ReferrerPolicyNoReferrerWhenDowngrade sends referrer to same-security-level destinations (default)
	ReferrerPolicyNoReferrerWhenDowngrade ReferrerPolicyOption = "no-referrer-when-downgrade"

	// ReferrerPolicyOrigin sends only origin (scheme, host, and port)
	ReferrerPolicyOrigin ReferrerPolicyOption = "origin"

	// ReferrerPolicyOriginWhenCrossOrigin sends full URL for same-origin, origin only for cross-origin
	ReferrerPolicyOriginWhenCrossOrigin ReferrerPolicyOption = "origin-when-cross-origin"

	// ReferrerPolicySameOrigin sends referrer for same-origin requests only
	ReferrerPolicySameOrigin ReferrerPolicyOption = "same-origin"

	// ReferrerPolicyStrictOrigin sends origin only, and only for same-security-level destinations
	ReferrerPolicyStrictOrigin ReferrerPolicyOption = "strict-origin"

	// ReferrerPolicyStrictOriginWhenCrossOrigin sends full URL for same-origin, origin for cross-origin same-security-level
	ReferrerPolicyStrictOriginWhenCrossOrigin ReferrerPolicyOption = "strict-origin-when-cross-origin"

	// ReferrerPolicyUnsafeURL always sends full URL (not recommended)
	ReferrerPolicyUnsafeURL ReferrerPolicyOption = "unsafe-url"
)

// COEPOption represents Cross-Origin-Embedder-Policy header values
type COEPOption string

const (
	// COEPUnsafeNone allows the document to fetch cross-origin resources without CORP header
	COEPUnsafeNone COEPOption = "unsafe-none"

	// COEPRequireCorp requires cross-origin resources to have CORP header
	COEPRequireCorp COEPOption = "require-corp"

	// COEPCredentialless allows cross-origin no-cors requests without CORP if credentials are omitted
	COEPCredentialless COEPOption = "credentialless"
)

// COOPOption represents Cross-Origin-Opener-Policy header values
type COOPOption string

const (
	// COOPUnsafeNone allows the document to be in the same browsing context group (default)
	COOPUnsafeNone COOPOption = "unsafe-none"

	// COOPSameOriginAllowPopups isolates context unless opened docs are same-origin and have COOP
	COOPSameOriginAllowPopups COOPOption = "same-origin-allow-popups"

	// COOPSameOrigin isolates the browsing context to same-origin documents only
	COOPSameOrigin COOPOption = "same-origin"
)

// CORPOption represents Cross-Origin-Resource-Policy header values
type CORPOption string

const (
	// CORPSameSite allows same-site origins to include the resource
	CORPSameSite CORPOption = "same-site"

	// CORPSameOrigin allows only same-origin requests to include the resource
	CORPSameOrigin CORPOption = "same-origin"

	// CORPCrossOrigin allows any origin to include the resource
	CORPCrossOrigin CORPOption = "cross-origin"
)

// ResponseHeadersBuilder configures response headers with secure defaults
type ResponseHeadersBuilder interface {
	// NoSniff explicitly enables X-Content-Type-Options: nosniff (enabled by default)
	NoSniff() ResponseHeadersBuilder

	// DisableNoSniff removes X-Content-Type-Options from defaults
	DisableNoSniff() ResponseHeadersBuilder

	// FrameOptions sets X-Frame-Options header
	// Use constants: FrameOptionDeny, FrameOptionSameOrigin
	// Or FrameOptionAllowFrom("https://example.com")
	// Default: FrameOptionSameOrigin
	FrameOptions(option FrameOption) ResponseHeadersBuilder

	// DisableFrameOptions removes X-Frame-Options from defaults
	DisableFrameOptions() ResponseHeadersBuilder

	// HSTS sets Strict-Transport-Security header
	// Only sent over HTTPS connections (when request.TLS != nil)
	// maxAge: seconds (must be >= 0), includeSubDomains: bool, preload: bool
	// Panics if maxAge < 0
	HSTS(maxAge int, includeSubDomains bool, preload bool) ResponseHeadersBuilder

	// ReferrerPolicy sets Referrer-Policy header
	// Use constants: ReferrerPolicyNoReferrer, ReferrerPolicyStrictOriginWhenCrossOrigin, etc.
	ReferrerPolicy(policy ReferrerPolicyOption) ResponseHeadersBuilder

	// CSP sets Content-Security-Policy header
	// Example: "default-src 'self'; script-src 'self' 'unsafe-inline'"
	CSP(policy string) ResponseHeadersBuilder

	// PermissionsPolicy sets Permissions-Policy header
	// Example: "geolocation=(), camera=(), microphone=()"
	PermissionsPolicy(policy string) ResponseHeadersBuilder

	// COEP sets Cross-Origin-Embedder-Policy header
	// Use constants: COEPUnsafeNone, COEPRequireCorp, COEPCredentialless
	COEP(policy COEPOption) ResponseHeadersBuilder

	// COOP sets Cross-Origin-Opener-Policy header
	// Use constants: COOPUnsafeNone, COOPSameOriginAllowPopups, COOPSameOrigin
	COOP(policy COOPOption) ResponseHeadersBuilder

	// CORP sets Cross-Origin-Resource-Policy header
	// Use constants: CORPSameSite, CORPSameOrigin, CORPCrossOrigin
	CORP(policy CORPOption) ResponseHeadersBuilder

	// Header adds a custom header with the given value
	// Name is used as-is (case-sensitive, not normalized)
	// Empty value sets empty header (removes header per HTTP spec)
	// No validation on header names
	Header(name string, value string) ResponseHeadersBuilder

	// Path initiates path-specific header configuration
	// Supports wildcard matching (e.g., "/api/*", "/admin/**")
	// Panics if called with empty path list
	Path(paths ...string) PathResponseHeadersBuilder

	// Build validates and creates the response headers filter
	Build() we.Filter
}

// PathResponseHeadersBuilder configures headers for specific paths
type PathResponseHeadersBuilder interface {
	// NoSniff explicitly enables X-Content-Type-Options: nosniff
	NoSniff() PathResponseHeadersBuilder

	// DisableNoSniff removes X-Content-Type-Options
	DisableNoSniff() PathResponseHeadersBuilder

	// FrameOptions sets X-Frame-Options header
	FrameOptions(option FrameOption) PathResponseHeadersBuilder

	// DisableFrameOptions removes X-Frame-Options
	DisableFrameOptions() PathResponseHeadersBuilder

	// HSTS sets Strict-Transport-Security header
	// Panics if maxAge < 0
	HSTS(maxAge int, includeSubDomains bool, preload bool) PathResponseHeadersBuilder

	// ReferrerPolicy sets Referrer-Policy header
	ReferrerPolicy(policy ReferrerPolicyOption) PathResponseHeadersBuilder

	// CSP sets Content-Security-Policy header
	CSP(policy string) PathResponseHeadersBuilder

	// PermissionsPolicy sets Permissions-Policy header
	PermissionsPolicy(policy string) PathResponseHeadersBuilder

	// COEP sets Cross-Origin-Embedder-Policy header
	COEP(policy COEPOption) PathResponseHeadersBuilder

	// COOP sets Cross-Origin-Opener-Policy header
	COOP(policy COOPOption) PathResponseHeadersBuilder

	// CORP sets Cross-Origin-Resource-Policy header
	CORP(policy CORPOption) PathResponseHeadersBuilder

	// Header adds a custom header with the given value
	Header(name string, value string) PathResponseHeadersBuilder

	// Disabled completely disables all headers for this path
	Disabled() PathResponseHeadersBuilder

	// Add completes path-specific configuration and returns to root builder
	Add() ResponseHeadersBuilder
}

// ResponseHeaders creates a new response headers filter builder with secure defaults
func ResponseHeaders() ResponseHeadersBuilder {
	return &responseHeadersBuilder{
		defaultConfig: &headerConfig{
			customHeaders: make(map[string]string),
		},
		pathConfigs: []*pathHeaderConfig{},
	}
}

// headerConfig holds header configuration
type headerConfig struct {
	// Security headers (pointers allow distinguishing unset/disabled/enabled)
	noSniff           *bool // nil=use default, true=enable, false=disable
	frameOptions      *FrameOption
	hsts              *hstsConfig
	referrerPolicy    *ReferrerPolicyOption
	csp               *string
	permissionsPolicy *string
	coep              *COEPOption
	coop              *COOPOption
	corp              *CORPOption

	// Free-form custom headers
	customHeaders map[string]string

	// Control flags
	disabled bool // if true, skip ALL headers for this path
}

// hstsConfig holds HSTS configuration
type hstsConfig struct {
	maxAge            int
	includeSubDomains bool
	preload           bool
}

// pathHeaderConfig holds path-specific configuration
type pathHeaderConfig struct {
	paths  []string
	config *headerConfig
}

// responseHeadersBuilder implements ResponseHeadersBuilder
type responseHeadersBuilder struct {
	defaultConfig *headerConfig
	pathConfigs   []*pathHeaderConfig
}

// NoSniff explicitly enables X-Content-Type-Options: nosniff
func (rb *responseHeadersBuilder) NoSniff() ResponseHeadersBuilder {
	trueVal := true
	rb.defaultConfig.noSniff = &trueVal
	return rb
}

// DisableNoSniff removes X-Content-Type-Options from defaults
func (rb *responseHeadersBuilder) DisableNoSniff() ResponseHeadersBuilder {
	falseVal := false
	rb.defaultConfig.noSniff = &falseVal
	return rb
}

// FrameOptions sets X-Frame-Options header
func (rb *responseHeadersBuilder) FrameOptions(option FrameOption) ResponseHeadersBuilder {
	rb.defaultConfig.frameOptions = &option
	return rb
}

// DisableFrameOptions removes X-Frame-Options from defaults
func (rb *responseHeadersBuilder) DisableFrameOptions() ResponseHeadersBuilder {
	empty := FrameOption("")
	rb.defaultConfig.frameOptions = &empty
	return rb
}

// HSTS sets Strict-Transport-Security header
func (rb *responseHeadersBuilder) HSTS(maxAge int, includeSubDomains bool, preload bool) ResponseHeadersBuilder {
	if maxAge < 0 {
		panic("HSTS maxAge must be non-negative")
	}
	rb.defaultConfig.hsts = &hstsConfig{
		maxAge:            maxAge,
		includeSubDomains: includeSubDomains,
		preload:           preload,
	}
	return rb
}

// ReferrerPolicy sets Referrer-Policy header
func (rb *responseHeadersBuilder) ReferrerPolicy(policy ReferrerPolicyOption) ResponseHeadersBuilder {
	rb.defaultConfig.referrerPolicy = &policy
	return rb
}

// CSP sets Content-Security-Policy header
func (rb *responseHeadersBuilder) CSP(policy string) ResponseHeadersBuilder {
	rb.defaultConfig.csp = &policy
	return rb
}

// PermissionsPolicy sets Permissions-Policy header
func (rb *responseHeadersBuilder) PermissionsPolicy(policy string) ResponseHeadersBuilder {
	rb.defaultConfig.permissionsPolicy = &policy
	return rb
}

// COEP sets Cross-Origin-Embedder-Policy header
func (rb *responseHeadersBuilder) COEP(policy COEPOption) ResponseHeadersBuilder {
	rb.defaultConfig.coep = &policy
	return rb
}

// COOP sets Cross-Origin-Opener-Policy header
func (rb *responseHeadersBuilder) COOP(policy COOPOption) ResponseHeadersBuilder {
	rb.defaultConfig.coop = &policy
	return rb
}

// CORP sets Cross-Origin-Resource-Policy header
func (rb *responseHeadersBuilder) CORP(policy CORPOption) ResponseHeadersBuilder {
	rb.defaultConfig.corp = &policy
	return rb
}

// Header adds a custom header with the given value
func (rb *responseHeadersBuilder) Header(name string, value string) ResponseHeadersBuilder {
	rb.defaultConfig.customHeaders[name] = value
	return rb
}

// Path initiates path-specific header configuration
func (rb *responseHeadersBuilder) Path(paths ...string) PathResponseHeadersBuilder {
	if len(paths) == 0 {
		panic("at least one path must be provided")
	}

	pathConfig := &pathHeaderConfig{
		paths: paths,
		config: &headerConfig{
			customHeaders: make(map[string]string),
		},
	}

	return &pathResponseHeadersBuilder{
		parent:     rb,
		pathConfig: pathConfig,
	}
}

// Build validates and creates the response headers filter
func (rb *responseHeadersBuilder) Build() we.Filter {
	// Apply defaults if not explicitly configured
	if rb.defaultConfig.noSniff == nil {
		trueVal := true
		rb.defaultConfig.noSniff = &trueVal
	}

	if rb.defaultConfig.frameOptions == nil {
		sameOrigin := FrameOptionSameOrigin
		rb.defaultConfig.frameOptions = &sameOrigin
	}

	// Build the filter with pathTree
	filter := &responseHeadersFilter{
		pathTree: pathTree.New[*headerConfig](),
	}

	// Add default config at / and /** to match all paths (/** doesn't match root /)
	if err := filter.pathTree.Add("/", rb.defaultConfig); err != nil {
		panic("failed to add default response headers config at /: " + err.Error())
	}
	if err := filter.pathTree.Add("/**", rb.defaultConfig); err != nil {
		panic("failed to add default response headers config at  /**: " + err.Error())
	}

	// Add path-specific configs
	for _, pathConfig := range rb.pathConfigs {
		for _, path := range pathConfig.paths {
			if err := filter.pathTree.Add(path, pathConfig.config); err != nil {
				panic("failed to add path-specific response headers config: " + err.Error())
			}
		}
	}

	return filter
}

// pathResponseHeadersBuilder implements PathResponseHeadersBuilder
type pathResponseHeadersBuilder struct {
	parent     *responseHeadersBuilder
	pathConfig *pathHeaderConfig
}

// NoSniff explicitly enables X-Content-Type-Options: nosniff
func (pb *pathResponseHeadersBuilder) NoSniff() PathResponseHeadersBuilder {
	trueVal := true
	pb.pathConfig.config.noSniff = &trueVal
	return pb
}

// DisableNoSniff removes X-Content-Type-Options
func (pb *pathResponseHeadersBuilder) DisableNoSniff() PathResponseHeadersBuilder {
	falseVal := false
	pb.pathConfig.config.noSniff = &falseVal
	return pb
}

// FrameOptions sets X-Frame-Options header
func (pb *pathResponseHeadersBuilder) FrameOptions(option FrameOption) PathResponseHeadersBuilder {
	pb.pathConfig.config.frameOptions = &option
	return pb
}

// DisableFrameOptions removes X-Frame-Options
func (pb *pathResponseHeadersBuilder) DisableFrameOptions() PathResponseHeadersBuilder {
	empty := FrameOption("")
	pb.pathConfig.config.frameOptions = &empty
	return pb
}

// HSTS sets Strict-Transport-Security header
func (pb *pathResponseHeadersBuilder) HSTS(maxAge int, includeSubDomains bool, preload bool) PathResponseHeadersBuilder {
	if maxAge < 0 {
		panic("HSTS maxAge must be non-negative")
	}
	pb.pathConfig.config.hsts = &hstsConfig{
		maxAge:            maxAge,
		includeSubDomains: includeSubDomains,
		preload:           preload,
	}
	return pb
}

// ReferrerPolicy sets Referrer-Policy header
func (pb *pathResponseHeadersBuilder) ReferrerPolicy(policy ReferrerPolicyOption) PathResponseHeadersBuilder {
	pb.pathConfig.config.referrerPolicy = &policy
	return pb
}

// CSP sets Content-Security-Policy header
func (pb *pathResponseHeadersBuilder) CSP(policy string) PathResponseHeadersBuilder {
	pb.pathConfig.config.csp = &policy
	return pb
}

// PermissionsPolicy sets Permissions-Policy header
func (pb *pathResponseHeadersBuilder) PermissionsPolicy(policy string) PathResponseHeadersBuilder {
	pb.pathConfig.config.permissionsPolicy = &policy
	return pb
}

// COEP sets Cross-Origin-Embedder-Policy header
func (pb *pathResponseHeadersBuilder) COEP(policy COEPOption) PathResponseHeadersBuilder {
	pb.pathConfig.config.coep = &policy
	return pb
}

// COOP sets Cross-Origin-Opener-Policy header
func (pb *pathResponseHeadersBuilder) COOP(policy COOPOption) PathResponseHeadersBuilder {
	pb.pathConfig.config.coop = &policy
	return pb
}

// CORP sets Cross-Origin-Resource-Policy header
func (pb *pathResponseHeadersBuilder) CORP(policy CORPOption) PathResponseHeadersBuilder {
	pb.pathConfig.config.corp = &policy
	return pb
}

// Header adds a custom header with the given value
func (pb *pathResponseHeadersBuilder) Header(name string, value string) PathResponseHeadersBuilder {
	pb.pathConfig.config.customHeaders[name] = value
	return pb
}

// Disabled completely disables all headers for this path
func (pb *pathResponseHeadersBuilder) Disabled() PathResponseHeadersBuilder {
	pb.pathConfig.config.disabled = true
	return pb
}

// Add completes path-specific configuration and returns to root builder
func (pb *pathResponseHeadersBuilder) Add() ResponseHeadersBuilder {
	pb.parent.pathConfigs = append(pb.parent.pathConfigs, pb.pathConfig)
	return pb.parent
}

// responseHeadersFilter implements we.Filter
type responseHeadersFilter struct {
	pathTree pathTree.Tree[*headerConfig]
}

// Filter implements the response headers filter logic
func (f *responseHeadersFilter) Filter(responseHeaders http.Header, scope we.RequestScope) error {
	request := scope.Request()

	// Get config for this path
	config := f.getConfigForPath(request.URL.Path)

	// If disabled, skip all processing
	if config == nil || config.disabled {
		return nil
	}

	// Apply NoSniff (default: enabled if not explicitly disabled)
	if config.noSniff == nil || *config.noSniff {
		responseHeaders.Set("X-Content-Type-Options", "nosniff")
	}

	// Apply FrameOptions (default: SAMEORIGIN if not explicitly disabled)
	if config.frameOptions == nil {
		responseHeaders.Set("X-Frame-Options", string(FrameOptionSameOrigin))
	} else if *config.frameOptions != "" {
		responseHeaders.Set("X-Frame-Options", string(*config.frameOptions))
	}

	// Apply HSTS (only over HTTPS)
	if config.hsts != nil && request.TLS != nil {
		value := fmt.Sprintf("max-age=%d", config.hsts.maxAge)
		if config.hsts.includeSubDomains {
			value += "; includeSubDomains"
		}
		if config.hsts.preload {
			value += "; preload"
		}
		responseHeaders.Set("Strict-Transport-Security", value)
	}

	// Apply other security headers
	if config.referrerPolicy != nil {
		responseHeaders.Set("Referrer-Policy", string(*config.referrerPolicy))
	}

	if config.csp != nil {
		responseHeaders.Set("Content-Security-Policy", *config.csp)
	}

	if config.permissionsPolicy != nil {
		responseHeaders.Set("Permissions-Policy", *config.permissionsPolicy)
	}

	if config.coep != nil {
		responseHeaders.Set("Cross-Origin-Embedder-Policy", string(*config.coep))
	}

	if config.coop != nil {
		responseHeaders.Set("Cross-Origin-Opener-Policy", string(*config.coop))
	}

	if config.corp != nil {
		responseHeaders.Set("Cross-Origin-Resource-Policy", string(*config.corp))
	}

	// Apply custom headers
	for name, value := range config.customHeaders {
		responseHeaders.Set(name, value)
	}

	return nil
}

// getConfigForPath returns the appropriate config for a given path
func (f *responseHeadersFilter) getConfigForPath(path string) *headerConfig {
	if config, _ := f.pathTree.Get(path); config != nil {
		return *config
	}
	return nil
}
