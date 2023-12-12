// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package events

import (
	"net/http"
)

// WE events act both as errors as well as flow control events. Usage of WE events allow filters, for example, to stop
// the flow chain with redirection or interruption events (the first to redirect to an sso login page, for example,
// while the second could be used to simply show a login form).
// For that reason, default WE events are provided with all (relevant) standard flavours of http status codes. While the
// event interface may be implemented by custom objects (as long as they follow the rules explained in the interface
// definition, theoretically it should not be required to do so. Only pre-defined events are used internally to control
// execution flow in specific ways (interruptions, internal forwards and redirections) Any custom event will be handled
// by the error handler, which could also be a custom implementation that implements any desired custom behaviour.
// Technically they are still considered an error as they represent a request that didn't follow the expected normal flow.

// These two events are special control events. They are not meant to interrupt/change flow, but are meant to inform
// the engine that a filter requests a change to be made in the incoming request location. They exist for the benefit
// of the standard security filter provided by the WE engine, but any filter implementation may use it for the same
// effect(s).
var (

	// Continue informs the engine that the filter chain should be interrupted and the handler (if any) should be invoked
	// for the path provided by the event as an attribute.
	Continue = &weEvent{statusCode: http.StatusContinue, category: 1, message: "Continue"}
	// Update informs the engine that the filter chain should continue to process the remaining filter in the chain, but
	// the requested path has been updated by the filter with the value provided in the event attribute.
	Update = &weEvent{statusCode: http.StatusProcessing, category: 1, message: "Update"}
)

// Interruptions. Events forcing a reply with a different content than the expected one. Only 2XX status
// that could typically be used in an interrupted flow (something that doesn't cause an error but also doesn't
// process the data from the request). Intended for Filters that may return a response before the handler is even
// called (for example, showing a page for an endpoint registered by an authentication provider of the security
// filter).
// Most of the standard 2XX responses should be set by the handlers themselves.
var (
	// OKInterruption Interrupt the flow and return the status 200 with whatever content is present in the event payload
	OKInterruption = &weEvent{statusCode: http.StatusOK, category: 2, message: "Ok"}
)

// Redirect events. These events interrupt the flow and should have the location in the event attribute. The location is set in the Content header
// Redirection events should only be returned by filters. Handlers that intend to return a redirection response should do so normally
// through the response
var (
	// MovedPermanentlyRedirect Interrupt the flow redirecting the client to whatever location the event carries in the attribute with status 301
	MovedPermanentlyRedirect = &weEvent{statusCode: http.StatusMovedPermanently, category: 3, message: "Moved Permanently"}
	// FoundRedirect Interrupt the flow redirecting the client to whatever location the event carries in the attribute with status 302
	FoundRedirect = &weEvent{statusCode: http.StatusFound, category: 3, message: "Found"}
	// TemporaryRedirectRedirect Interrupt the flow redirecting the client to whatever location the event carries in the attribute with status 307
	TemporaryRedirectRedirect = &weEvent{statusCode: http.StatusTemporaryRedirect, category: 3, message: "Temporary Redirect"}
	// PermanentRedirectRedirect Interrupt the flow redirecting the client to whatever location the event carries in the attribute with status 308
	PermanentRedirectRedirect = &weEvent{statusCode: http.StatusPermanentRedirect, category: 3, message: "Permanent Redirect"}
)

// Request errors are events intended to reply to clients informing them of an invalid request (client side mal-formed request or application errors)
// the result is an interrupted flow immediately returning to the client with either just the status code or with whatever payload
// the event will carry. Filters and handlers should return semantically correct errors to the client. As default, a selection of common errors is
// provided. For other specific errors, new weEvents can be created with the corresponding status code.
var (
	// BadRequestError Should be returned by handlers or filters when the request does not comply with the expected input for the called endpoint
	BadRequestError = &weEvent{statusCode: http.StatusBadRequest, category: 4, message: "Bad Request"}
	// UnauthorizedError is the standard error that should be returned for authentication failure
	UnauthorizedError = &weEvent{statusCode: http.StatusUnauthorized, category: 4, message: "Unauthorized"}
	// ForbiddenError should be returned by handlers or filter for authenticated calls that have no access to the requested endpoint
	ForbiddenError = &weEvent{statusCode: http.StatusForbidden, category: 4, message: "Forbidden"}
	// NotFoundError may be returned by filters or handlers for unknown requested resources (acceptable response in case of rest apis),
	// but for normal flows it will be used internally by the engine itself to tag calls to unknown endpoints.
	NotFoundError = &weEvent{statusCode: http.StatusNotFound, category: 4, message: "Not Found"}
	// MethodNotAllowedError may be returned by handlers or filters to notify the client that the request has an unsupported method.
	MethodNotAllowedError = &weEvent{statusCode: http.StatusMethodNotAllowed, category: 4, message: "Method Not Allowed"}
	// NotAcceptableError may be returned by handlers or filters to notify the client that the request is not acceptable.
	NotAcceptableError = &weEvent{statusCode: http.StatusNotAcceptable, category: 4, message: "Not Acceptable"}
	// GoneError may be returned by handlers to inform the client the addressed object is gone. Typical response for a successful DELETE request
	GoneError = &weEvent{statusCode: http.StatusGone, category: 4, message: "Gone"}
	// RequestEntityTooLargeError may be returned by handlers or filters to notify the client that the request has a larger content than expected or supported.
	RequestEntityTooLargeError = &weEvent{statusCode: http.StatusRequestEntityTooLarge, category: 4, message: "Entity Too Large"}
	// RequestURITooLongError may be returned by handlers or filters to notify the client that the request has a longer uri than expected/supported (for example, too many query parameters)
	RequestURITooLongError = &weEvent{statusCode: http.StatusRequestURITooLong, category: 4, message: "URI Too Long"}
	// UnsupportedMediaTypeError may be returned by handlers or filters to notify the client that the content-type is not supported.
	UnsupportedMediaTypeError = &weEvent{statusCode: http.StatusUnsupportedMediaType, category: 4, message: "Unsupported Media Type"}
)

// Server Errors typically used to handle internal panics and inform the client of a server side runtime error.
var (
	// InternalServerError non-specific server side error. Any uncaught panic will result in a 500 error
	InternalServerError = &weEvent{statusCode: http.StatusInternalServerError, category: 5, message: "Internal Server Error"}
)
