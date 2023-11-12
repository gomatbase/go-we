// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package we

import (
	"net/http"
)

type ResponseWriter interface {
	http.ResponseWriter
	isWritten() bool
}

type responseWriter struct {
	httpResponseWriter http.ResponseWriter
	written            bool
}

func (rw *responseWriter) Header() http.Header {
	return rw.httpResponseWriter.Header()
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	rw.written = true
	return rw.httpResponseWriter.Write(data)
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.written = true
	rw.httpResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) isWritten() bool {
	return rw.written
}
