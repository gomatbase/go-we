// Copyright 2023-2026 GOM. All rights reserved.
// Since 24/10/2023 By GOM
// Licensed under MIT License

package util

import (
	"encoding/json"
	"io"

	"github.com/gomatbase/go-we"
)

// ReadJsonBody reads and unmarshals the JSON request body into the provided type T.
// Returns an error if the body cannot be decoded.
// EOF errors are ignored to handle empty request bodies gracefully.
//
// Example:
//
//	type CreateUserRequest struct {
//	    Username string `json:"username"`
//	    Email    string `json:"email"`
//	}
//
//	func handler(w http.ResponseWriter, scope we.RequestScope) error {
//	    req, err := util.ReadJsonBody[CreateUserRequest](scope)
//	    if err != nil {
//	        return events.BadRequestError.WithPayload("application/json",
//	            []byte(`{"error":"Invalid JSON"}`))
//	    }
//	    // Use req.Username, req.Email...
//	    return nil
//	}
func ReadJsonBody[T any](scope we.RequestScope) (*T, error) {
	result := new(T)
	if e := json.NewDecoder(scope.Request().Body).Decode(result); e != nil && e != io.EOF {
		return nil, e
	}
	return result, nil
}
