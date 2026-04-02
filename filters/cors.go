// Copyright 2026 GOM. All rights reserved.
// Since 01/04/2026 By GOM
// Licensed under MIT License

package filters

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/pathTree"
)

// CorsFilterBuilder configures Cross-Origin Resource Sharing (CORS) rules.
// It supports both default and path-specific CORS configurations with wildcard path matching.
type CorsFilterBuilder interface {
	// AllowedOrigins sets allowed origins for the default configuration (applies to all paths unless overridden).
	// Use ["*"] to allow any origin.
	// Panics if called with empty list.
	AllowedOrigins(origins ...string) CorsFilterBuilder

	// AllowedMethods sets allowed HTTP methods for the default configuration.
	// Default: ["GET", "POST", "HEAD"]
	AllowedMethods(methods ...string) CorsFilterBuilder

	// AllowedHeaders sets allowed request headers for the default configuration.
	// Default: ["Accept", "Content-Type", "X-Requested-With"]
	AllowedHeaders(headers ...string) CorsFilterBuilder

	// ExposedHeaders sets headers that browsers are allowed to access for the default configuration.
	// Default: []
	ExposedHeaders(headers ...string) CorsFilterBuilder

	// AllowCredentials enables cookies/auth in CORS requests for the default configuration.
	// Default: false
	AllowCredentials() CorsFilterBuilder

	// MaxAge sets preflight cache time in seconds for the default configuration.
	// Default: 3600 (1 hour)
	// Panics if negative value provided.
	MaxAge(seconds int) CorsFilterBuilder

	// Path initiates path-specific CORS configuration for the provided paths.
	// Supports wildcard matching (e.g., "/api/*", "/admin/**").
	// Returns a PathCorsConfigBuilder for configuring CORS rules for specific paths.
	// Panics if called with empty path list.
	Path(paths ...string) PathCorsConfigBuilder

	// Build validates and creates the CORS filter.
	// Panics if no default or path-specific configuration exists.
	Build() we.Filter
}

// PathCorsConfigBuilder configures CORS rules for specific paths.
type PathCorsConfigBuilder interface {
	// AllowedOrigins sets allowed origins for the configured paths.
	AllowedOrigins(origins ...string) PathCorsConfigBuilder

	// AllowedMethods sets allowed HTTP methods for the configured paths.
	AllowedMethods(methods ...string) PathCorsConfigBuilder

	// AllowedHeaders sets allowed request headers for the configured paths.
	AllowedHeaders(headers ...string) PathCorsConfigBuilder

	// ExposedHeaders sets exposed headers for the configured paths.
	ExposedHeaders(headers ...string) PathCorsConfigBuilder

	// AllowCredentials enables credentials for the configured paths.
	AllowCredentials() PathCorsConfigBuilder

	// MaxAge sets preflight cache time for the configured paths.
	MaxAge(seconds int) PathCorsConfigBuilder

	// Disabled explicitly disables CORS for the configured paths.
	// This is useful when you have a default CORS configuration but want to
	// disable CORS for specific paths (e.g., internal endpoints, health checks).
	// When disabled, no CORS headers will be added for matching paths.
	Disabled() PathCorsConfigBuilder

	// Add completes path-specific configuration and returns to root builder.
	Add() CorsFilterBuilder
}

// Cors creates a new CORS filter builder with sensible defaults.
func Cors() CorsFilterBuilder {
	return &corsFilterBuilder{
		defaultConfig: &corsConfig{
			allowedOrigins:   []string{},
			allowedMethods:   []string{"GET", "POST", "HEAD"},
			allowedHeaders:   []string{"Accept", "Content-Type", "X-Requested-With"},
			exposedHeaders:   []string{},
			maxAge:           3600,
			allowCredentials: false,
		},
		pathConfigs: []*pathCorsConfig{},
	}
}

// corsConfig holds the CORS configuration settings
type corsConfig struct {
	allowedOrigins   []string
	allowedMethods   []string
	allowedHeaders   []string
	exposedHeaders   []string
	maxAge           int
	allowCredentials bool
	allowAll         bool // cached flag: true if allowedOrigins contains "*"
	disabled         bool // if true, CORS is explicitly disabled for this path
}

// pathCorsConfig holds path-specific CORS configuration
type pathCorsConfig struct {
	paths  []string
	config *corsConfig
}

// corsFilterBuilder implements CorsFilterBuilder
type corsFilterBuilder struct {
	defaultConfig *corsConfig
	pathConfigs   []*pathCorsConfig
}

// AllowedOrigins sets allowed origins for the default configuration
func (cb *corsFilterBuilder) AllowedOrigins(origins ...string) CorsFilterBuilder {
	if len(origins) == 0 {
		panic("at least one origin must be provided")
	}
	cb.defaultConfig.allowedOrigins = origins
	cb.defaultConfig.allowAll = len(origins) == 1 && origins[0] == "*"
	return cb
}

// AllowedMethods sets allowed HTTP methods for the default configuration
func (cb *corsFilterBuilder) AllowedMethods(methods ...string) CorsFilterBuilder {
	if len(methods) == 0 {
		panic("at least one method must be provided")
	}
	cb.defaultConfig.allowedMethods = methods
	return cb
}

// AllowedHeaders sets allowed request headers for the default configuration
func (cb *corsFilterBuilder) AllowedHeaders(headers ...string) CorsFilterBuilder {
	if len(headers) == 0 {
		panic("at least one header must be provided")
	}
	cb.defaultConfig.allowedHeaders = headers
	return cb
}

// ExposedHeaders sets exposed headers for the default configuration
func (cb *corsFilterBuilder) ExposedHeaders(headers ...string) CorsFilterBuilder {
	cb.defaultConfig.exposedHeaders = headers
	return cb
}

// AllowCredentials enables credentials for the default configuration
func (cb *corsFilterBuilder) AllowCredentials() CorsFilterBuilder {
	cb.defaultConfig.allowCredentials = true
	return cb
}

// MaxAge sets preflight cache time for the default configuration
func (cb *corsFilterBuilder) MaxAge(seconds int) CorsFilterBuilder {
	if seconds < 0 {
		panic("maxAge must be non-negative")
	}
	cb.defaultConfig.maxAge = seconds
	return cb
}

// Path initiates path-specific CORS configuration
func (cb *corsFilterBuilder) Path(paths ...string) PathCorsConfigBuilder {
	if len(paths) == 0 {
		panic("at least one path must be provided")
	}

	pathConfig := &pathCorsConfig{
		paths: paths,
		config: &corsConfig{
			allowedOrigins:   []string{},
			allowedMethods:   []string{"GET", "POST", "HEAD"},
			allowedHeaders:   []string{"Accept", "Content-Type", "X-Requested-With"},
			exposedHeaders:   []string{},
			maxAge:           3600,
			allowCredentials: false,
		},
	}

	return &pathCorsConfigBuilder{
		parent:     cb,
		pathConfig: pathConfig,
	}
}

// Build validates and creates the CORS filter
func (cb *corsFilterBuilder) Build() we.Filter {
	// Validate that we have at least some configuration
	hasDefaultConfig := len(cb.defaultConfig.allowedOrigins) > 0
	hasPathConfigs := len(cb.pathConfigs) > 0

	if !hasDefaultConfig && !hasPathConfigs {
		panic("at least one CORS configuration (default or path-specific) must be provided")
	}

	// Validate default config if present
	if hasDefaultConfig {
		validateConfig(cb.defaultConfig)
	}

	// Validate path configs if present
	for _, pathConfig := range cb.pathConfigs {
		validateConfig(pathConfig.config)
	}

	// Build the filter with pathTree
	filter := &corsFilter{
		pathTree: pathTree.New[*corsConfig](),
	}

	// Add default config to pathTree with /** wildcard if present
	if hasDefaultConfig {
		if err := filter.pathTree.Add("/**", cb.defaultConfig); err != nil {
			panic("failed to add default CORS config to pathTree: " + err.Error())
		}
	}

	// Add path-specific configs to pathTree
	for _, pathConfig := range cb.pathConfigs {
		for _, path := range pathConfig.paths {
			if err := filter.pathTree.Add(path, pathConfig.config); err != nil {
				panic("failed to add path to CORS filter: " + err.Error())
			}
		}
	}

	return filter
}

// validateConfig validates a CORS configuration
func validateConfig(config *corsConfig) {
	// Skip validation for disabled configs
	if config.disabled {
		return
	}

	// Check for invalid combination of credentials and wildcard origin
	if config.allowCredentials && config.allowAll {
		panic("cannot use AllowCredentials with wildcard origin '*' (violates CORS specification)")
	}
}

// pathCorsConfigBuilder implements PathCorsConfigBuilder
type pathCorsConfigBuilder struct {
	parent     *corsFilterBuilder
	pathConfig *pathCorsConfig
}

// AllowedOrigins sets allowed origins for the configured paths
func (pcb *pathCorsConfigBuilder) AllowedOrigins(origins ...string) PathCorsConfigBuilder {
	if len(origins) == 0 {
		panic("at least one origin must be provided")
	}
	pcb.pathConfig.config.allowedOrigins = origins
	pcb.pathConfig.config.allowAll = len(origins) == 1 && origins[0] == "*"
	return pcb
}

// AllowedMethods sets allowed HTTP methods for the configured paths
func (pcb *pathCorsConfigBuilder) AllowedMethods(methods ...string) PathCorsConfigBuilder {
	if len(methods) == 0 {
		panic("at least one method must be provided")
	}
	pcb.pathConfig.config.allowedMethods = methods
	return pcb
}

// AllowedHeaders sets allowed request headers for the configured paths
func (pcb *pathCorsConfigBuilder) AllowedHeaders(headers ...string) PathCorsConfigBuilder {
	if len(headers) == 0 {
		panic("at least one header must be provided")
	}
	pcb.pathConfig.config.allowedHeaders = headers
	return pcb
}

// ExposedHeaders sets exposed headers for the configured paths
func (pcb *pathCorsConfigBuilder) ExposedHeaders(headers ...string) PathCorsConfigBuilder {
	pcb.pathConfig.config.exposedHeaders = headers
	return pcb
}

// AllowCredentials enables credentials for the configured paths
func (pcb *pathCorsConfigBuilder) AllowCredentials() PathCorsConfigBuilder {
	pcb.pathConfig.config.allowCredentials = true
	return pcb
}

// MaxAge sets preflight cache time for the configured paths
func (pcb *pathCorsConfigBuilder) MaxAge(seconds int) PathCorsConfigBuilder {
	if seconds < 0 {
		panic("maxAge must be non-negative")
	}
	pcb.pathConfig.config.maxAge = seconds
	return pcb
}

// Disabled explicitly disables CORS for the configured paths
func (pcb *pathCorsConfigBuilder) Disabled() PathCorsConfigBuilder {
	pcb.pathConfig.config.disabled = true
	return pcb
}

// Add completes path-specific configuration and returns to root builder
func (pcb *pathCorsConfigBuilder) Add() CorsFilterBuilder {
	pcb.parent.pathConfigs = append(pcb.parent.pathConfigs, pcb.pathConfig)
	return pcb.parent
}

// corsFilter implements we.Filter
type corsFilter struct {
	pathTree pathTree.Tree[*corsConfig]
}

// Filter implements the CORS filter logic
func (cf *corsFilter) Filter(responseHeaders http.Header, scope we.RequestScope) error {
	request := scope.Request()
	origin := request.Header.Get("Origin")

	// No Origin header means this is not a CORS request
	if origin == "" {
		return nil
	}

	// Find the appropriate CORS configuration for this path
	config := cf.getConfigForPath(request.URL.Path)

	// If no config found or config is explicitly disabled, skip CORS
	if config == nil || config.disabled {
		return nil
	}

	// Check if origin is allowed
	if !cf.isOriginAllowed(origin, config) {
		// Origin not allowed - don't add CORS headers (browser will block)
		return nil
	}

	// Set Access-Control-Allow-Origin
	if config.allowAll {
		responseHeaders.Set("Access-Control-Allow-Origin", "*")
	} else {
		responseHeaders.Set("Access-Control-Allow-Origin", origin)
		// Add Vary header to indicate that response varies by Origin
		responseHeaders.Add("Vary", "Origin")
	}

	// Set credentials header if enabled
	if config.allowCredentials {
		responseHeaders.Set("Access-Control-Allow-Credentials", "true")
	}

	// Set exposed headers if any
	if len(config.exposedHeaders) > 0 {
		responseHeaders.Set("Access-Control-Expose-Headers", strings.Join(config.exposedHeaders, ", "))
	}

	// Handle preflight (OPTIONS) requests
	if request.Method == "OPTIONS" {
		responseHeaders.Set("Access-Control-Allow-Methods", strings.Join(config.allowedMethods, ", "))
		responseHeaders.Set("Access-Control-Allow-Headers", strings.Join(config.allowedHeaders, ", "))
		responseHeaders.Set("Access-Control-Max-Age", strconv.Itoa(config.maxAge))

		// Return event with 204 No Content for preflight
		return events.New(http.StatusNoContent, "No Content")
	}

	// For non-preflight requests, continue to handler
	return nil
}

// getConfigForPath returns the appropriate CORS config for a given path
func (cf *corsFilter) getConfigForPath(path string) *corsConfig {
	// Look up config in pathTree (includes root config at /** and path-specific configs)
	if config, _ := cf.pathTree.Get(path); config != nil {
		return *config
	}

	// No config available
	return nil
}

// isOriginAllowed checks if an origin is allowed by the config
func (cf *corsFilter) isOriginAllowed(origin string, config *corsConfig) bool {
	// Wildcard allows all origins
	if config.allowAll {
		return true
	}

	// Check if origin is in the allowed list
	for _, allowed := range config.allowedOrigins {
		if allowed == origin {
			return true
		}
	}

	return false
}
