// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package errors

import (
	"fmt"
)

// WeError we error interface to be used as errors as well as flow control events. It always associates the error with
// the expected response status code associated to the event/error
type WeError interface {
	// Error returns the error message prepended by the status code
	error
	// StatusCode returns the status code associated to the error
	StatusCode() int
	// Payload returns the payload carried by the error. Payloads have data that may be used when producing a response
	Payload() any
	// WithPayload returns a new identical error with the given payload
	WithPayload(any) WeError
	// Is checks if the given error is identical to this one. Two errors are considered identical if they have exactly
	// the same status code and message, disregarding the payload
	Is(err error) bool
}

// New creates a new we error with the given status code and message and no payload
func New(statusCode int, message string) WeError {
	return NewPayload(statusCode, message, nil)
}

// NewPayload creates a new we error with the given status code, message and payload
func NewPayload(statusCode int, message string, payload any) WeError {
	return &weError{
		statusCode: statusCode,
		message:    message,
		payload:    payload,
	}
}

// weError is a WeError implementation
type weError struct {
	statusCode int
	message    string
	payload    any
}

func (wee *weError) Error() string {
	return fmt.Sprintf("%d: %s", wee.statusCode, wee.message)
}

func (wee *weError) StatusCode() int {
	return wee.statusCode
}

func (wee *weError) Payload() any {
	return wee.payload
}

func (wee *weError) WithPayload(payload any) WeError {
	return &weError{
		statusCode: wee.statusCode,
		message:    wee.message,
		payload:    payload,
	}
}

func (wee *weError) Is(err error) bool {
	if wee == err {
		return true
	}
	if weerr, ok := err.(*weError); ok {
		return wee.statusCode == weerr.StatusCode() && wee.message == weerr.message
	}
	return false
}
