// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package errors

import (
	"net/http"
)

// WE errors act both as errors as well as flow control events. Usage of we errors allow filters, for example, to stop the flow chain with an error
// or with a normal response that should intercept the request (redirects or login forms, for example)
// For that reason, default we errors are provided with all standard flavours of status codes.
// Technically they are still considered an error as they represent a request that didn't follow the expected normal flow.

var (
	// Interruptions. Errors to be used as flow control events forcing a reply with a different content than the expected one. Only 2XX status
	// that could typically be used in an interrupted flow (something that doesn't cause an error but also doesn't process the data from the request)
	// are provided as default errors.
	OKInterruption                   = &weError{statusCode: http.StatusOK, message: "Ok"}
	NonAuthoritativeInfoInterruption = &weError{statusCode: http.StatusNonAuthoritativeInfo, message: "Non Authoritative Info"}
	NoContentInterruption            = &weError{statusCode: http.StatusNoContent, message: "No Content"}
	ResetContentInterruption         = &weError{statusCode: http.StatusResetContent, message: "Reset Content"}
	AlreadyReportedInterruption      = &weError{statusCode: http.StatusAlreadyReported, message: "Already Reported"}

	// Redirects. Errors to be used as flow control events and not necessarily as an error
	MultipleChoicesRedirect   = &weError{statusCode: http.StatusMultipleChoices, message: "Multiple Choices"}
	MovedPermanentlyRedirect  = &weError{statusCode: http.StatusMovedPermanently, message: "Moved Permanently"}
	FoundRedirect             = &weError{statusCode: http.StatusFound, message: "Found"}
	SeeOtherRedirect          = &weError{statusCode: http.StatusSeeOther, message: "See Other"}
	NotModifiedRedirect       = &weError{statusCode: http.StatusNotModified, message: "Not Modified"}
	UseProxyRedirect          = &weError{statusCode: http.StatusUseProxy, message: "Use Proxy"}
	TemporaryRedirectRedirect = &weError{statusCode: http.StatusTemporaryRedirect, message: "Temporary Redirect"}
	PermanentRedirectRedirect = &weError{statusCode: http.StatusPermanentRedirect, message: "Permanent Redirect"}

	// Request Errorss
	BadRequestError                   = &weError{statusCode: http.StatusBadRequest, message: "Bad Request"}
	UnauthorizedError                 = &weError{statusCode: http.StatusUnauthorized, message: "Unauthorized"}
	PaymentRequiredErrorError         = &weError{statusCode: http.StatusPaymentRequired, message: "Payment Required"}
	ForbiddenError                    = &weError{statusCode: http.StatusForbidden, message: "Forbidden"}
	NotFoundError                     = &weError{statusCode: http.StatusNotFound, message: "Not Found"}
	MethodNotAllowedError             = &weError{statusCode: http.StatusMethodNotAllowed, message: "Method Not Allowed"}
	NotAcceptableError                = &weError{statusCode: http.StatusNotAcceptable, message: "Not Acceptable"}
	ProxyAuthRequiredError            = &weError{statusCode: http.StatusProxyAuthRequired, message: "Proxy Authentication Required"}
	RequestTimeoutError               = &weError{statusCode: http.StatusRequestTimeout, message: "Request Timeout"}
	ConflictError                     = &weError{statusCode: http.StatusConflict, message: "Conflict"}
	GoneError                         = &weError{statusCode: http.StatusGone, message: "Gone"}
	LengthRequiredError               = &weError{statusCode: http.StatusLengthRequired, message: "Content Length Required"}
	PreconditionFailedError           = &weError{statusCode: http.StatusPreconditionFailed, message: "Precondition Failedt"}
	RequestEntityTooLargeError        = &weError{statusCode: http.StatusRequestEntityTooLarge, message: "Entity Too Large"}
	RequestURITooLongError            = &weError{statusCode: http.StatusRequestURITooLong, message: "URI Too Long"}
	UnsupportedMediaTypeError         = &weError{statusCode: http.StatusUnsupportedMediaType, message: "Unsupported Media Type"}
	RequestedRangeNotSatisfiableError = &weError{statusCode: http.StatusRequestedRangeNotSatisfiable, message: "Requested Range Not Satisfiable"}
	ExpectationFailedError            = &weError{statusCode: http.StatusExpectationFailed, message: "Expectation Failed"}
	MisdirectedRequestError           = &weError{statusCode: http.StatusMisdirectedRequest, message: "Misdirected Request"}
	UnprocessableEntityError          = &weError{statusCode: http.StatusUnprocessableEntity, message: "Unprocessable Entity"}
	LockedError                       = &weError{statusCode: http.StatusLocked, message: "Locked"}
	FailedDependencyError             = &weError{statusCode: http.StatusFailedDependency, message: "Failed Dependency"}
	TooEarlyError                     = &weError{statusCode: http.StatusTooEarly, message: "Too Early"}
	UpgradeRequiredError              = &weError{statusCode: http.StatusUpgradeRequired, message: "Upgrade Required"}
	PreconditionRequiredError         = &weError{statusCode: http.StatusPreconditionRequired, message: "Precondition Required"}
	TooManyRequestsError              = &weError{statusCode: http.StatusTooManyRequests, message: "Too Many Requests"}
	RequestHeaderFieldsTooLargeError  = &weError{statusCode: http.StatusRequestHeaderFieldsTooLarge, message: "Request Header Fields Too Large"}
	UnavailableForLevalReasonsError   = &weError{statusCode: http.StatusUnavailableForLegalReasons, message: "Unavailable For Legal Reasons"}

	// Server Errors
	InternalServerError                = &weError{statusCode: http.StatusInternalServerError, message: "Internal Server Error"}
	NotImplementedError                = &weError{statusCode: http.StatusNotImplemented, message: "Not Implemented"}
	BadGatewayError                    = &weError{statusCode: http.StatusBadGateway, message: "Bad Gateway"}
	ServiceUnavailableError            = &weError{statusCode: http.StatusServiceUnavailable, message: "Service Unavailable"}
	GatewayTimeoutError                = &weError{statusCode: http.StatusGatewayTimeout, message: "Gateway Timeout"}
	InsufficientStorageError           = &weError{statusCode: http.StatusInsufficientStorage, message: "Insufficient Storage"}
	LoopDetectedError                  = &weError{statusCode: http.StatusLoopDetected, message: "Loop Detected"}
	NotExtendedError                   = &weError{statusCode: http.StatusNotExtended, message: "Not Extended"}
	NetworkAuthenticationRequiredError = &weError{statusCode: http.StatusNetworkAuthenticationRequired, message: "Network Authentication Required"}
)
