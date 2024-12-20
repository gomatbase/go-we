// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/pathTree"
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
	HasSession() bool
}

type Headers interface {
}

type requestScope struct {
	request    *http.Request
	attributes map[string]interface{}
	variables  map[string]string
	session    *Session
}

func (rs *requestScope) HasSession() bool {
	return rs.session != nil
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

func (rs *requestScope) updateEndpoint(endpoint string) {
	parts := strings.Split(endpoint, "?")
	rs.request.URL.Path = parts[0]
	if len(parts) > 1 {
		rs.request.URL.RawQuery = parts[1]
	}
}

type HandlerFunction func(ResponseWriter, RequestScope) error

type FilterFunction func(http.Header, RequestScope) error

func (ff FilterFunction) Filter(headers http.Header, scope RequestScope) error {
	return ff(headers, scope)
}

type Filter interface {
	Filter(http.Header, RequestScope) error
}

type WebEngine interface {
	SetSessionManager(sessionManager SessionManager)
	Handle(path string, handler HandlerFunction)
	HandleMethod(method string, path string, handler HandlerFunction)
	AddFilter(filter Filter)
	Listen(addr string) error
	Handler() http.Handler
}

// A Web state structure
type webEngine struct {
	filters        []Filter
	matchTrees     map[string]pathTree.Tree[HandlerFunction]
	sessionManager SessionManager
	errorHandler   ErrorHandler
}

func (wc *webEngine) Handle(path string, handler HandlerFunction) {
	wc.HandleMethod("ALL", path, handler)
}

func (wc *webEngine) HandleMethod(method string, path string, handler HandlerFunction) {
	tree, found := wc.matchTrees[method]
	if !found {
		tree = pathTree.New[HandlerFunction]()
		wc.matchTrees[method] = tree
	}
	tree.Add(path, handler)
}

func (wc *webEngine) AddFilter(filter Filter) {
	wc.filters = append(wc.filters, filter)
}

func (wc *webEngine) SetSessionManager(sessionManager SessionManager) {
	wc.sessionManager = sessionManager
}

func (wc *webEngine) Listen(addr string) error {
	if wc.errorHandler == nil {
		wc.errorHandler = &errorHandler{
			errorCatalog:   make(map[string]ErrorHandler),
			weErrorCatalog: make(map[int]ErrorHandler),
		}
	}
	fmt.Println("Listening on", addr)
	return http.ListenAndServe(addr, wc.Handler())
}

func (wc *webEngine) Handler() http.Handler {
	if wc.errorHandler == nil {
		wc.errorHandler = &errorHandler{
			errorCatalog:   make(map[string]ErrorHandler),
			weErrorCatalog: make(map[int]ErrorHandler),
		}
	}
	return http.HandlerFunc(wc.process)
}

func (wc *webEngine) findHandler(r *http.Request) (handler *HandlerFunction, variables map[string]string) {
	method := r.Method
	pt, found := wc.matchTrees[method]
	if !found {
		method = "ALL"
		pt = wc.matchTrees[method]
	}

	// match the incoming endpoint to a registered handler
	handler, variables = pt.Get(r.URL.Path)
	if handler == nil && found {
		pt = wc.matchTrees["ALL"]
		handler, variables = pt.Get(r.URL.Path)
	}

	return
}

func (wc *webEngine) process(w http.ResponseWriter, r *http.Request) {

	rw := &responseWriter{httpResponseWriter: w}
	defer func() {
		if recovery := recover(); recovery != nil {
			// this is an unhandled panic recovery, print stack trace
			debug.PrintStack()
			wc.errorHandler.HandleError(rw, events.InternalServerError, nil)
		}
	}()

	// request context is always created fresh for an incoming request
	scope := &requestScope{
		request:    r,
		attributes: make(map[string]interface{}),
	}
	if wc.sessionManager != nil {
		scope.session = wc.sessionManager.GetHttpSession(w, r)
	}

	// First process all filters in registration order
	var e error
loop:
	for _, filter := range wc.filters {
		// ignore the error for now
		e = filter.Filter(rw.Header(), scope)
		if e != nil {
			if event, isEvent := e.(events.WeEvent); isEvent {
				switch event.Category() {
				case events.RequestFlow:
					scope.updateEndpoint(event.Attribute())
					if events.Continue.Is(event) {
						break loop
					}
				case events.Interruption:
					w.Header().Set("Content-type", event.Payload().ContentTypeHint)
					w.WriteHeader(event.StatusCode())
					w.Write(event.Payload().Content)
				case events.Redirection:
					w.Header().Set("Location", event.Attribute())
					w.WriteHeader(event.StatusCode())
				default:
					wc.errorHandler.HandleError(rw, event, scope)
				}
			} else {
				wc.errorHandler.HandleError(rw, e, scope)
			}
			return
		}
	}

	// All filters processed successfully, time to handle the request
	handler, variables := wc.findHandler(r)

	// We first check if the request is incoming for a handled endpoint. If not we just return 404
	if handler == nil {
		wc.errorHandler.HandleError(rw, events.NotFoundError, nil)
		return
	}

	scope.variables = variables

	if e = (*handler)(rw, scope); e != nil {
		wc.errorHandler.HandleError(rw, e, scope)
	}

}

func New() WebEngine {
	return &webEngine{
		matchTrees: map[string]pathTree.Tree[HandlerFunction]{"ALL": pathTree.New[HandlerFunction]()},
	}
}
