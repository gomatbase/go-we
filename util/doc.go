// Copyright 2023-2026 GOM. All rights reserved.
// Since 24/10/2023 By GOM
// Licensed under MIT License

// Package util provides utility functions for common HTTP request and response operations.
//
// This package includes helpers for:
//   - JSON request body parsing with ReadJsonBody
//   - JSON response writing with ReplyJson and DumpedReplyJson
//
// These utilities simplify working with JSON in HTTP handlers and reduce boilerplate code.
//
// Example usage:
//
//	import "github.com/gomatbase/go-we/util"
//
//	type CreateUserRequest struct {
//	    Username string `json:"username"`
//	    Email    string `json:"email"`
//	}
//
//	type UserResponse struct {
//	    ID       string `json:"id"`
//	    Username string `json:"username"`
//	}
//
//	func createUserHandler(w http.ResponseWriter, scope we.RequestScope) error {
//	    // Parse JSON request body
//	    req, err := util.ReadJsonBody[CreateUserRequest](scope)
//	    if err != nil {
//	        return events.BadRequestError
//	    }
//
//	    // Create user...
//	    user := UserResponse{ID: "123", Username: req.Username}
//
//	    // Send JSON response
//	    return util.ReplyJson(w, http.StatusCreated, user)
//	}
package util
