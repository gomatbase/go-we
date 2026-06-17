// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package filters

import (
	"net/http"

	we "github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/pathTree"
)

// BodySizeLimit provides HTTP request body size limiting capabilities.
// It enforces maximum body sizes to prevent DoS attacks and resource exhaustion.
type BodySizeLimit interface {
	we.Filter
}

// BodySizeLimitBuilder is used to build a BodySizeLimit filter with custom configuration.
type BodySizeLimitBuilder interface {
	// MaxSize sets the maximum allowed request body size in bytes for all paths.
	// Default: 10MB (10485760 bytes)
	MaxSize(bytes int64) BodySizeLimitBuilder
	// Path configures body size limits for specific paths.
	Path(paths ...string) BodySizeLimitPathBuilder
	// Build creates and returns the configured BodySizeLimit filter.
	Build() BodySizeLimit
}

// BodySizeLimitPathBuilder configures body size limits for specific paths.
type BodySizeLimitPathBuilder interface {
	// MaxSize sets the maximum allowed request body size in bytes for the configured paths
	// and returns to the main builder to continue configuration.
	MaxSize(bytes int64) BodySizeLimitBuilder
}

const (
	// DefaultMaxBodySize is the default maximum body size (10MB)
	DefaultMaxBodySize int64 = 10485760
)

// bodySizeLimit is the implementation of BodySizeLimit
type bodySizeLimit struct {
	defaultMaxSize int64
	pathLimits     pathTree.Tree[int64]
}

// Filter implements the we.Filter interface
func (bsl *bodySizeLimit) Filter(header http.Header, scope we.RequestScope) error {
	request := scope.Request()
	maxSize := bsl.defaultMaxSize

	// Check if there's a path-specific limit
	if pathLimit, _ := bsl.pathLimits.Get(request.URL.Path); pathLimit != nil {
		maxSize = *pathLimit
	}

	// Check Content-Length header if available
	if request.ContentLength > 0 && request.ContentLength > maxSize {
		return events.RequestEntityTooLargeError.WithPayload(
			"text/plain",
			[]byte("Request body exceeds maximum allowed size"),
		)
	}

	// Wrap the body reader to enforce the limit
	// This prevents reading more than maxSize bytes
	request.Body = http.MaxBytesReader(nil, request.Body, maxSize)

	return nil
}

// bodySizeLimitBuilder is the implementation of BodySizeLimitBuilder
type bodySizeLimitBuilder struct {
	filter *bodySizeLimit
}

// MaxSize sets the default maximum body size
func (bslb *bodySizeLimitBuilder) MaxSize(bytes int64) BodySizeLimitBuilder {
	if bytes <= 0 {
		panic("max body size must be greater than 0")
	}
	bslb.filter.defaultMaxSize = bytes
	return bslb
}

// Path initializes a path-specific configuration
func (bslb *bodySizeLimitBuilder) Path(paths ...string) BodySizeLimitPathBuilder {
	if len(paths) == 0 {
		panic("at least one path must be provided")
	}
	return &bodySizeLimitPathBuilder{
		builder: bslb,
		paths:   paths,
	}
}

// Build returns the configured filter
func (bslb *bodySizeLimitBuilder) Build() BodySizeLimit {
	return bslb.filter
}

// bodySizeLimitPathBuilder is the implementation of BodySizeLimitPathBuilder
type bodySizeLimitPathBuilder struct {
	builder *bodySizeLimitBuilder
	paths   []string
}

// MaxSize sets the maximum body size for the configured paths and returns the builder
func (bslpb *bodySizeLimitPathBuilder) MaxSize(bytes int64) BodySizeLimitBuilder {
	if bytes <= 0 {
		panic("max body size must be greater than 0")
	}
	for _, path := range bslpb.paths {
		if e := bslpb.builder.filter.pathLimits.Add(path, bytes); e != nil {
			panic(e.Error())
		}
	}
	return bslpb.builder
}

// DefaultBodySizeLimit creates a new BodySizeLimitBuilder with default configuration.
// Default max size is 10MB for all paths.
//
// Example:
//
//	filter := filters.DefaultBodySizeLimit().
//	    MaxSize(5 * 1024 * 1024).  // 5MB default
//	    Path("/api/upload").
//	        MaxSize(100 * 1024 * 1024).  // 100MB for uploads
//	    Path("/api/import").
//	        MaxSize(50 * 1024 * 1024).   // 50MB for imports
//	    Build()
//
//	engine := we.New().
//	    Filter(filter).
//	    Build()
func DefaultBodySizeLimit() BodySizeLimitBuilder {
	return &bodySizeLimitBuilder{
		filter: &bodySizeLimit{
			defaultMaxSize: DefaultMaxBodySize,
			pathLimits:     pathTree.New[int64](),
		},
	}
}
