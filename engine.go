// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/pathTree"
)

// RequestScope is a wrapper for an incoming http.Request, providing additional methods to simplify usage and access to
// request attributes, parameters, path variables and session values.
type RequestScope interface {
	// Request returns the underlying http.Request object
	Request() *http.Request
	// Var returns the value of a path variable. String is empty if trying to access a variable which doesn't exist for the path
	Var(string) string
	// LookupVar returns the value of a path variable as Var does, but also indicates if in case of an empty value if it's because the variable does not exist
	LookupVar(string) (string, bool)
	// Parameter returns the value of a query parameter. String is empty if the parameter was not sent
	Parameter(string) string
	// Parameters returns all values of a query parameter. Nil if the parameter was not sent
	Parameters(string) []string
	// LookupParameter returns the value of a query parameter as Parameter does, but also indicates if in case of an empty value if it's because the parameter was not sent
	LookupParameter(string) (string, bool)
	// LookupParameters returns all values of a query parameter as Parameters does, but also indicates if in case of an empty value if it's because the parameter was not sent
	LookupParameters(string) ([]string, bool)
	// Get returns the value of an attribute set in the request scope
	Get(string) any
	// Set sets an attribute in the request scope
	Set(string, any)
	// GetFromSession returns the value of an attribute set in the session. Returns nil if sessions are not enabled
	GetFromSession(string) any
	// SetInSession sets an attribute in the session. Does nothing if sessions are not enabled
	SetInSession(string, any)
	// HasSession returns true if sessions are enabled
	HasSession() bool
}

// requestScope is the RequestScope implementation
type requestScope struct {
	// the underlying http.Request object
	request *http.Request
	// request scope attributes
	attributes map[string]any
	// path variables extracted from the request
	variables map[string]string
	// session object if sessions are enabled
	session *Session
}

// HasSession checks if sessions are active
func (rs *requestScope) HasSession() bool {
	return rs.session != nil
}

// Request returns the underlying http.Request object
func (rs *requestScope) Request() *http.Request {
	return rs.request
}

// Var returns the value of a path variable.
func (rs *requestScope) Var(name string) string {
	return rs.variables[name]
}

// LookupVar returns the value of a path variable and if it's present in the request
func (rs *requestScope) LookupVar(name string) (value string, found bool) {
	value, found = rs.variables[name]
	return
}

// Parameter returns the value of a query parameter
func (rs *requestScope) Parameter(name string) string {
	return rs.request.URL.Query().Get(name)
}

// Parameters returns all values of a query parameter
func (rs *requestScope) Parameters(name string) []string {
	return rs.request.URL.Query()[name]
}

// LookupParameter returns the value of a query parameter and if it's present in the request
func (rs *requestScope) LookupParameter(name string) (string, bool) {
	if values, found := rs.request.URL.Query()[name]; found {
		if len(values) > 0 {
			return values[0], true
		}
	}
	return "", false
}

// LookupParameters returns all values of a query parameter and if the parameter is present in the request
func (rs *requestScope) LookupParameters(name string) ([]string, bool) {
	if values, found := rs.request.URL.Query()[name]; found {
		return values, true
	}
	return nil, false
}

// Get returns the value of an attribute set in the request scope
func (rs *requestScope) Get(key string) any {
	return rs.attributes[key]
}

// Set sets an attribute in the request scope
func (rs *requestScope) Set(key string, value any) {
	rs.attributes[key] = value
}

// GetFromSession returns the value of an attribute set in the session
func (rs *requestScope) GetFromSession(key string) any {
	if rs.session != nil {
		return rs.session.Attributes[key]
	}
	return nil
}

// SetInSession sets an attribute in the session
func (rs *requestScope) SetInSession(key string, value any) {
	if rs.session != nil {
		rs.session.Attributes[key] = value
	}
}

// updateEndpoint updates the query in the request path. Used to handle redirections with updated queries.
func (rs *requestScope) updateEndpoint(endpoint string) {
	parts := strings.Split(endpoint, "?")
	rs.request.URL.Path = parts[0]
	if len(parts) > 1 {
		rs.request.URL.RawQuery = parts[1]
	}
}

// HandlerFunction defines the method signature for a request handler. Similar to http.Handler but using the wrapped
// response and request objects
type HandlerFunction func(ResponseWriter, RequestScope) error

// FilterFunction is a function wrapper to allow simple functions to be used as filters instead of the Filter interface
// implementation.
type FilterFunction func(http.Header, RequestScope) error

// Filter is the interface for a filter implementation, which simply calls the function itself.
func (ff FilterFunction) Filter(headers http.Header, scope RequestScope) error {
	return ff(headers, scope)
}

// Filter is the interface for a filter implementation
type Filter interface {
	// Filter is the method the method called when the filter is applied to a request. Filters may
	// introspect the request and add attributes to session or request scope, which can be used further down the line,
	// either by other filters or the request handler itself. The filter may also add specific response headers. Added
	// response headers may be overwritten by later filters or the request handler.
	Filter(http.Header, RequestScope) error
}

// WebEngine defines the main methods provided by a go-we engine
type WebEngine interface {
	// SetSessionManager sets the session manager to be used by the engine. Setting a session manager implicitly enables sessions
	SetSessionManager(sessionManager SessionManager)
	// HookShutdownFunction expects a pointer to a function which will be set with function that can be called for an immediate shutdown
	HookShutdownFunction(shutdown *func() error)
	// HookGraciousShutdownFunction expects a pointer to a function which will be set with function that can be called
	// for a gracious shutdown, waiting up to waitingTime until it forces the listener to shutdown
	HookGraciousShutdownFunction(shutdown *func(waitingTime time.Duration) error)
	// Handle registers a handler for a path. The handler will be called for all HTTP methods
	Handle(path string, handler HandlerFunction)
	// HandleMethod registers a handler for a path and a specific HTTP method. functions registered by HandleMethod
	// will take precedence over any function registered by Handle for the same path.
	HandleMethod(method string, path string, handler HandlerFunction)
	// AddFilter registers a filter to be applied to all incoming requests. Filters are applied in the order they are registered
	AddFilter(filter Filter)
	// Listen starts the engine listening on the provided address. The engine will block until the server is stopped.
	Listen(addr string) error
	// ListenWithTls starts the engine listening on the provided address using https. A certificate and key file locations must be provided.
	ListenWithTls(addr string, certFile string, keyFile string) error
	// ListenWithTlsOptions starts the engine listening on the provided address using https. The full tls configuration must be provided.
	ListenWithTlsOptions(addr string, config *tls.Config) error
	// Handler returns the http.Handler implementation for the engine. This can be used to embed the engine in another standard http server configured independently
	Handler() http.Handler
}

// webEngine is a WebEngine implementation
type webEngine struct {
	// List of filters to be applied to incoming requests
	filters []Filter
	// Map of path trees for each HTTP method having a registered handler function
	matchTrees map[string]pathTree.Tree[HandlerFunction]
	// Session manager to be used by the engine, if enabled
	sessionManager SessionManager
	// ErrorHandler to be used by the engine for any unchecked panics or errors
	errorHandler ErrorHandler
	// the server the engine is running on, if managed by the engine itself (with Listen* methods)
	server *http.Server
}

// HookShutdownFunction updates the provided function placeholder with a function that can graciously shutdown the server
func (wc *webEngine) HookShutdownFunction(shutdown *func() error) {
	*shutdown = func() error {
		if wc.server == nil {
			return fmt.Errorf("listener not managed by engine")
		}
		return wc.server.Close()
	}
}

// HookGraciousShutdownFunction updates the provided function placeholder with a function that can graciously shutdown the server
func (wc *webEngine) HookGraciousShutdownFunction(shutdown *func(time.Duration) error) {
	*shutdown = func(waitingTime time.Duration) error {
		if wc.server == nil {
			return fmt.Errorf("listener not managed by engine")
		}
		timingOutContext, cancel := context.WithTimeout(context.Background(), waitingTime)
		e := wc.server.Shutdown(timingOutContext)
		if errors.Is(e, context.DeadlineExceeded) {
			// Even after the deadline the server will graciously wait for any hanging handlers to finish. We forcely close the channels
			// attach any additional error that the close may have raised
			e = errors.Join(e, wc.server.Close())
		}
		cancel() // sanity cleanup
		return e
	}
}

// Handle registers a handler for a path. The handler will be called for all HTTP methods
func (wc *webEngine) Handle(path string, handler HandlerFunction) {
	wc.HandleMethod("ALL", path, handler)
}

// HandleMethod registers a handler for a path and a specific HTTP method. functions registered by HandleMethod
// will take precedence over any function registered by Handle for the same path.
func (wc *webEngine) HandleMethod(method string, path string, handler HandlerFunction) {
	tree, found := wc.matchTrees[method]
	if !found {
		tree = pathTree.New[HandlerFunction]()
		wc.matchTrees[method] = tree
	}
	if e := tree.Add(path, handler); e != nil {
		panic(e)
	}
}

// AddFilter registers a filter to be applied to all incoming requests. Filters are applied in the order they are registered
func (wc *webEngine) AddFilter(filter Filter) {
	wc.filters = append(wc.filters, filter)
}

// SetSessionManager sets the session manager to be used by the engine. Setting a session manager implicitly enables sessions
func (wc *webEngine) SetSessionManager(sessionManager SessionManager) {
	wc.sessionManager = sessionManager
}

// Listen starts the engine listening on the provided address. The engine will block until the server is stopped.
func (wc *webEngine) Listen(addr string) error {
	fmt.Println("Listening on", addr)
	wc.server = &http.Server{Addr: addr, Handler: wc.Handler()}
	return wc.server.ListenAndServe()
}

// ListenWithTls starts the engine listening on the provided address using https. A certificate and key file locations must be provided.
func (wc *webEngine) ListenWithTls(addr string, certFile string, keyFile string) error {
	fmt.Println("Listening tls on", addr)
	wc.server = &http.Server{Addr: addr, Handler: wc.Handler()}
	return wc.server.ListenAndServeTLS(certFile, keyFile)
}

// ListenWithTlsOptions starts the engine listening on the provided address using https. The full tls configuration must be provided.
func (wc *webEngine) ListenWithTlsOptions(addr string, config *tls.Config) error {
	if config == nil {
		return fmt.Errorf("tls config is nil")
	}

	srv := &http.Server{Addr: addr, Handler: wc.Handler()}
	l, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	defer l.Close()

	fmt.Println("Listening tls on", addr)
	return srv.Serve(tls.NewListener(l, config))
}

// Handler returns the http.Handler implementation for the engine. This can be used to embed the engine in another standard http server configured independently
func (wc *webEngine) Handler() http.Handler {
	if wc.errorHandler == nil {
		wc.errorHandler = &errorHandler{
			errorCatalog:   make(map[string]ErrorHandler),
			weErrorCatalog: make(map[int]ErrorHandler),
			marshaller:     ErrorMarshallerFunction(defaultErrorMarshaller),
		}
	}
	return http.HandlerFunc(wc.process)
}

// findHandler checks if there are any handlers registered to handle the request path, in which case it will
// also parse the path for any path variables defined. It returns both the handler and the path variables, which
// may be null if the path has no variables defined.
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

// process actually handles incoming requests.
//
// It starts by wrapping the response writer with the go-we writer which allows checking if the response has
// already started to be written. This will be used to be able to graciously handle redirections or any other
// flow interruption, as is the case of errors raised.
//
// A request scope is then created to wrap the incoming http.Request. The request scope is always initialized
// with a fresh set of request scope attributes, and if a sessions are enabled, either create a new session or
// attach an existing session (found through the session manager which will typically use a session cookie).
//
// Filters are then applied in registration order, and it may return an event to interrupt the normal flow of the
// request. Events can be errors or simply flow interruptions, like redirections or requests to break the filter chain.
//
// If no interruptions, redirections or errors are returned by the filters, the internal path tree is looked up
// for the request path, and if a handler is found it will be invoked with the request scope being updated with any
// configured variables for the path.
//
// Failure to find a suitable handle will result in a not found event which will be handled by the error manager.
//
// Any event/error returned by the handler will be handled by the error manager.
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
		attributes: make(map[string]any),
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
