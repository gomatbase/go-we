// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package errors

import (
	"net/http"
)

var (
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
