// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"net/http"
)

type RequestScope interface {
	Request() *http.Request
	Var(string) string
	LookupVar(string) (string, bool)
	Parameter(string) string
	Parameters(string) []string
	LookupParameter(string) (string, bool)
	LookupParameters(string) ([]string, bool)
	Get(string) interface{}
	Set(string, interface{})
	GetFromSession(string) interface{}
	SetInSession(string, interface{})
}

type requestScope struct {
	request    *http.Request
	attributes map[string]interface{}
	variables  map[string]string
	session    *Session
}

func (rs *requestScope) Request() *http.Request {
	return rs.request
}

func (rs *requestScope) Var(name string) string {
	return rs.variables[name]
}

func (rs *requestScope) LookupVar(name string) (value string, found bool) {
	value, found = rs.variables[name]
	return
}

func (rs *requestScope) Parameter(name string) string {
	return rs.request.URL.Query().Get(name)
}

func (rs *requestScope) Parameters(name string) []string {
	return rs.request.URL.Query()[name]
}

func (rs *requestScope) LookupParameter(name string) (string, bool) {
	if values, found := rs.request.URL.Query()[name]; found {
		if len(values) > 0 {
			return values[0], true
		}
	}
	return "", false
}

func (rs *requestScope) LookupParameters(name string) ([]string, bool) {
	if values, found := rs.request.URL.Query()[name]; found {
		return values, true
	}
	return nil, false
}

func (rs *requestScope) Get(key string) interface{} {
	return rs.attributes[key]
}

func (rs *requestScope) Set(key string, value interface{}) {
	rs.attributes[key] = value
}

func (rs *requestScope) GetFromSession(key string) interface{} {
	if rs.session != nil {
		return rs.session.Attributes[key]
	}
	return nil
}

func (rs *requestScope) SetInSession(key string, value interface{}) {
	if rs.session != nil {
		rs.session.Attributes[key] = value
	}
}

type HandlerFunction func(http.ResponseWriter, RequestScope) error

type FilterFunction func(http.ResponseWriter, RequestScope) (bool, error)

func (ff FilterFunction) Filter(w http.ResponseWriter, scope RequestScope) (bool, error) {
	return ff(w, scope)
}

type Filter interface {
	Filter(http.ResponseWriter, RequestScope) (bool, error)
}
type WebEngine interface {
	SetSessionManager(sessionManager SessionManager)
	Handle(path string, handler HandlerFunction)
	HandleMethod(method string, path string, handler HandlerFunction)
	AddFilter(filter FilterFunction)
	Listen(addr string) error
	Handler() http.Handler
}

// A Web state structure
type webEngine struct {
	filters        []FilterFunction
	matchTrees     map[string]*pathTree
	sessionManager SessionManager
}

func (wc *webEngine) Handle(path string, handler HandlerFunction) {
	wc.HandleMethod("ALL", path, handler)
}

func (wc *webEngine) HandleMethod(method string, path string, handler HandlerFunction) {
	pathTree, found := wc.matchTrees[method]
	if !found {
		pathTree = newPathTree()
		wc.matchTrees[method] = pathTree
	}
	pathTree.addHandler(path, handler)
}

func (wc *webEngine) AddFilter(filter FilterFunction) {
	wc.filters = append(wc.filters, filter)
}

func (wc *webEngine) SetSessionManager(sessionManager SessionManager) {
	wc.sessionManager = sessionManager
}

func (wc *webEngine) Listen(addr string) error {
	return http.ListenAndServe(addr, wc.Handler())
}

func (wc *webEngine) Handler() http.Handler {
	return http.HandlerFunc(wc.process)
}

func (wc *webEngine) process(w http.ResponseWriter, r *http.Request) {

	method := r.Method
	pt, found := wc.matchTrees[method]
	if !found {
		method = "ALL"
		pt = wc.matchTrees[method]
	}

	// match the incoming endpoint to a registered handler
	handler, variables := pt.getHandlerAndPathVariables(r.URL.Path)
	if handler == nil && found {
		pt = wc.matchTrees["ALL"]
		handler, variables = pt.getHandlerAndPathVariables(r.URL.Path)
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
	scope := &requestScope{
		request:    r,
		attributes: make(map[string]interface{}),
		variables:  variables,
		session:    session,
	}

	// First process all filters in registration order
	filtersSuccessful := true
	for _, filter := range wc.filters {
		// ignore the error for now
		if filtersSuccessful, _ = filter(w, scope); !filtersSuccessful {
			// Any of the filters may stop the process at any time. it's up to the filter to provide a proper  response handling
			break
		}
	}

	// All filters processed successfully, time to handle the request
	if filtersSuccessful {
		handler.(HandlerFunction)(w, scope)
	}

}

func New() WebEngine {
	return &webEngine{
		matchTrees: map[string]*pathTree{"ALL": newPathTree()},
	}
}
