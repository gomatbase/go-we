// Copyright 2023-2026 GOM. All rights reserved.
// Since 24/10/2023 By GOM
// Licensed under MIT License

package util

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func replyJson(w http.ResponseWriter, status int, value any) ([]byte, error) {
	if body, e := json.Marshal(value); e == nil {
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(status)
		if _, e = w.Write(body); e != nil {
			return nil, e
		}
		return body, nil
	} else {
		return nil, e
	}
}

// ReplyJson marshals the provided value to JSON and writes it to the response with the given status code.
// Sets the Content-Type header to "application/json".
// Returns an error if marshalling or writing fails.
//
// Example:
//
//	type UserResponse struct {
//	    ID       string `json:"id"`
//	    Username string `json:"username"`
//	}
//
//	func handler(w http.ResponseWriter, scope we.RequestScope) error {
//	    user := UserResponse{ID: "123", Username: "john"}
//	    return util.ReplyJson(w, http.StatusOK, user)
//	}
func ReplyJson(w http.ResponseWriter, status int, value any) error {
	_, e := replyJson(w, status, value)
	return e
}

// DumpedReplyJson works like ReplyJson but also prints the response body to stdout for debugging.
// Useful during development to inspect JSON responses.
//
// Example:
//
//	func handler(w http.ResponseWriter, scope we.RequestScope) error {
//	    data := map[string]string{"status": "ok"}
//	    return util.DumpedReplyJson(w, http.StatusOK, data)
//	    // Prints: response: code: 200 , body: {"status":"ok"}
//	}
func DumpedReplyJson(w http.ResponseWriter, status int, value any) error {
	if body, e := replyJson(w, status, value); e == nil {
		fmt.Println("response: code:", status, ", body:", string(body))
	} else {
		return e
	}

	return nil
}
