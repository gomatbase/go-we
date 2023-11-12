// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package errors

type WeError interface {
	error
	StatusCode() int
	Payload() any
	WithPayload(any) WeError
}

func New(statusCode int, message string, payload any) WeError {
	return &weError{
		statusCode: statusCode,
		message:    message,
		payload:    payload,
	}
}

type weError struct {
	statusCode int
	message    string
	payload    any
}

func (wee *weError) Error() string {
	return wee.message
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
