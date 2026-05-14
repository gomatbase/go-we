// Copyright 2026 GOM. All rights reserved.
// Since 14/05/2026 By GOM
// Licensed under MIT License

package convert

import (
	"net/http"

	"github.com/gomatbase/go-we"
)

func Handler(handler http.Handler) we.HandlerFunction {
	return func(w http.ResponseWriter, scope we.RequestScope) error {
		handler.ServeHTTP(w, scope.Request())
		return nil
	}
}

func HandlerFunc(handlerFunc http.HandlerFunc) we.HandlerFunction {
	return func(w http.ResponseWriter, scope we.RequestScope) error {
		handlerFunc(w, scope.Request())
		return nil
	}
}
