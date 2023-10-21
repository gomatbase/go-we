// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"net/http"
)

// http.Request wrapper providing a web engine context that allows filters to enrich it and expose payloads for
// request handlers as well as filters posterior filters (filters are triggered in the order they were added to the
// engine), parsed path variables for endpoints that expect them and a Session object if sessions are in use.
type RequestContext struct {
	Request   *http.Request
	Context   map[string]interface{}
	Variables map[string]string
	Session   *Session
}

// Utility interface for a web engine request handler, for atomic (single handler function) Handler structures
type Handler interface {
	Handle(w http.ResponseWriter, context *RequestContext) error
}

// Utility interface for a web engine filter, for atomic (single filter function) Filter structures
type Filter interface {
	Filter(w http.ResponseWriter, context *RequestContext) (bool, error)
}

// A Web state structure
type WebEngine struct {
	filters        []func(w http.ResponseWriter, context *RequestContext) (bool, error)
	matchTrees     map[string]*pathTree
	sessionManager SessionManager
}

// Create a new Web Engine with default behaviours and settings. Namely, no filters will be present, sessions will be
// used with a default Session time out and using and in-memory Session manager.
func NewWebEngine() *WebEngine {
	webContext := new(WebEngine)
	webContext.filters = []func(w http.ResponseWriter, context *RequestContext) (bool, error){}
	webContext.matchTrees = map[string]*pathTree{"ALL": newPathTree()}
	return webContext
}

// Activates or deactivates the use of sessions in the web engine. By default, sessions are used.
func (wc *WebEngine) SetSessionManager(sessionManager SessionManager) {
	wc.sessionManager = sessionManager
}

// creates a new request context from an incoming request
func newRequestContext(r *http.Request, variables map[string]string, session *Session) *RequestContext {
	requestContext := new(RequestContext)
	requestContext.Context = make(map[string]interface{})
	requestContext.Request = r
	requestContext.Variables = variables
	requestContext.Session = session

	return requestContext
}

// Add a filter function to the engine
func (wc *WebEngine) AddFilterFunc(filter func(w http.ResponseWriter, context *RequestContext) (bool, error)) {
	wc.filters = append(wc.filters, filter)
}

// Add a handling function to the engine
func (wc *WebEngine) AddHandlerFunc(path string, handler func(w http.ResponseWriter, context *RequestContext) error) {
	wc.matchTrees["ALL"].addHandler(path, handler)
}

func (wc *WebEngine) AddMethodHandlerFunc(method string, path string, handler func(w http.ResponseWriter, context *RequestContext) error) {
	pathTree, found := wc.matchTrees[method]
	if !found {
		pathTree = newPathTree()
		wc.matchTrees[method] = pathTree
	}
	pathTree.addHandler(path, handler)
}

// Utility function to attach a handler to a path
func (wc *WebEngine) AddHandler(path string, handler Handler) {
	wc.AddMethodHandlerFunc("ALL", path, handler.Handle)
}

func (wc *WebEngine) AddMethodHandler(method string, path string, handler Handler) {
	wc.AddMethodHandlerFunc(method, path, handler.Handle)
}

// http.Handler implementation of the WebEngine which will handle the http request life-cycle, including Session
// management, filter processing and error handling
func (wc *WebEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	method := r.Method
	pathTree, found := wc.matchTrees[method]
	if !found {
		method = "ALL"
		pathTree = wc.matchTrees[method]
	}

	// match the incoming endpoint to a registered handler
	handler, variables := pathTree.getHandlerAndPathVariables(r.URL.Path)
	if handler == nil && found {
		pathTree = wc.matchTrees["ALL"]
		handler, variables = pathTree.getHandlerAndPathVariables(r.URL.Path)
	}

	// We first check if the request is incoming for a handled endpoint. If not we just return 404
	if handler == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	var session *Session
	if wc.sessionManager != nil {
		session = wc.sessionManager.GetHttpSession(w, r)
	}

	// request context is always created fresh for an incoming request
	requestContext := newRequestContext(r, variables, session)

	// First process all filters in registration order
	filtersSuccessful := true
	for _, filter := range wc.filters {
		// ignore the error for now
		if filtersSuccessful, _ = filter(w, requestContext); !filtersSuccessful {
			// Any of the filters may stop the process at any time. it's up to the filter to provide a proper  response handling
			break
		}
	}

	// All filters processed successfully, time to handle the request
	if filtersSuccessful {
		handler.(func(w http.ResponseWriter, context *RequestContext) error)(w, requestContext)
	}

}
