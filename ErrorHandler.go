// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package we

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we/events"
)

type ErrorHandler interface {
	HandleError(ResponseWriter, error, RequestScope)
}

type ErrorMarshaller interface {
	Marshal(error) ([]byte, string)
}

type ErrorMarshallerFunction func(error) (responseBody []byte, mimeType string)

func (emf ErrorMarshallerFunction) Marshal(err error) ([]byte, string) {
	return emf(err)
}

func defaultErrorMarshaller(err error) ([]byte, string) {
	if weError, isType := err.(events.WeEvent); isType {
		if payload := weError.Payload(); payload != nil {
			return payload.Content, payload.ContentTypeHint
		}
	}
	return nil, ""
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
	if weError, isType := err.(events.WeEvent); isType {
		statusCode = weError.StatusCode()
		if handler, found := eh.weErrorCatalog[statusCode]; found {
			handler.HandleError(w, err, scope)
			return
		}
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
