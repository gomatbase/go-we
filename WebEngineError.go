// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

type WebEngineError struct {
	message string
}

func (wee *WebEngineError) Error() string {
	return wee.message
}

func newWebEngineError(message string) *WebEngineError {
	result := new(WebEngineError)
	result.message = message
	return result
}

