// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

// Generic Web Engine error with a simple error message. Plain error interface implementation.
type WebEngineError struct {
	message string
}

// error interface implementation returning the error message
func (wee *WebEngineError) Error() string {
	return wee.message
}

// Creates a new Web Engine error with the given message
func newWebEngineError(message string) *WebEngineError {
	result := new(WebEngineError)
	result.message = message
	return result
}

