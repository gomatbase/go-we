// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package we

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we/errors"
)

type ErrorHandler interface {
	HandleError(ResponseWriter, error, RequestScope)
}

type ErrorMarshaller interface {
	Marshal(error) ([]byte, string)
}

type errorHandler struct {
	marshaller     ErrorMarshaller
	errorCatalog   map[string]ErrorHandler
	weErrorCatalog map[int]ErrorHandler
}

func (eh *errorHandler) HandleError(w ResponseWriter, err error, scope RequestScope) {
	// first let's see if it's still possible to reply
	if w.isWritten() {
		fmt.Println("Failed to handle error as writer has already been written to")
		return
	}

	statusCode := http.StatusInternalServerError
	if weError, isType := err.(errors.WeError); isType {
		if handler, found := eh.weErrorCatalog[weError.StatusCode()]; found {
			handler.HandleError(w, err, scope)
			return
		}
		statusCode = weError.StatusCode()
	} else if handler, found := eh.errorCatalog[err.Error()]; found {
		handler.HandleError(w, err, scope)
		return
	}

	if eh.marshaller != nil {
		if content, mimeType := eh.marshaller.Marshal(err); content != nil {
			w.Header().Set("Content-Type", mimeType)
			w.WriteHeader(statusCode)
			if _, e := w.Write(content); e != nil {
				fmt.Println("Failed to write error response", e)
			}
			return
		}
	}

	w.WriteHeader(statusCode)
}
