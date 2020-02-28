// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"log"
	"net/http"
	"time"
)


type RequestContext struct {
	Request   *http.Request
	Context    map[string]interface{}
	Variables  map[string]string
	Session   *Session
}

type Handler interface {
	Handle(w http.ResponseWriter, context *RequestContext) error
}

type Filter interface {
	Filter(w http.ResponseWriter, context *RequestContext) (bool, error)
}

type WebEngine struct {
	filters           []func(w http.ResponseWriter, context *RequestContext) (bool, error)
	matchTree         *pathTree
	sessionManager    SessionManager
	useSessions       bool
	sessionCookieName string
	sessionTimeout    float64
}

func NewWebEngine() *WebEngine {
	webContext := new(WebEngine)
	webContext.filters = []func(w http.ResponseWriter, context *RequestContext) (bool,error){}
	webContext.matchTree = newPathTree()
	webContext.sessionManager = NewInMemorySessionManager()
	webContext.sessionTimeout = DEFAULT_SESSION_TIMEOUT
	webContext.useSessions = true
	webContext.sessionCookieName = "weSessionId"
	return webContext
}

func (wc *WebEngine) SetSessionTimeout(seconds float64) {
	wc.sessionTimeout = seconds
}

func (wc *WebEngine) UseSessions(flag bool) {
	wc.useSessions = flag
}

func newRequestContext(r *http.Request, variables map[string]string, session *Session) *RequestContext {
	requestContext := new(RequestContext)
	requestContext.Context = make(map[string]interface{})
	requestContext.Request = r
	requestContext.Variables = variables
	requestContext.Session = session

	return requestContext
}

func (wc *WebEngine) AddFilterFunc(filter func(w http.ResponseWriter, context *RequestContext) (bool, error)) {
	wc.filters = append(wc.filters, filter)
}

func (wc *WebEngine) AddHandlerFunc(path string, handler func(w http.ResponseWriter, context *RequestContext) error) {
	wc.matchTree.addHandler(path, handler)
}

func (wc *WebEngine) AddHandler(path string, handler Handler) {
	wc.AddHandlerFunc(path, handler.Handle)
}

func (wc *WebEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	handler, variables := wc.matchTree.getHandlerAndPathVariables(r.URL.Path)

	// We first check if the request is incoming for handled endpoint. If not we just return 404
	if handler == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// fetch an existing session or just create one, if using sessions, to add to the request context
	log.Println("fetching session")
	session := wc.fetchOrCreateSession(r)
	if session != nil && session.Status == NEW {
		// let's add the session if to the cookies
		http.SetCookie(w, &http.Cookie{Name:wc.sessionCookieName, Value: session.SessionId, Path: "/" })
	}
	// request context is always created fresh fo an incoming request
	requestContext := newRequestContext(r, variables, session)

	// First process all filters in registration order
	var filtersSuccessful bool
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

	// update session use and Status
	session.Status = EXISTING
	session.lastUse = time.Now()
}

func (wc *WebEngine) fetchOrCreateSession(r *http.Request) *Session {

	// if sessions are meant to be used (default), we first try to get it from a session cookie
	if wc.useSessions {
		sessionToken, cookieFetchError := r.Cookie(wc.sessionCookieName)
		if cookieFetchError != http.ErrNoCookie {
			if session := wc.sessionManager.Get(sessionToken.Value); session != nil {
				log.Println("found session", session)
				log.Println("checking for expiration", wc.sessionTimeout, time.Now(), session.lastUse, time.Now().Sub(session.lastUse).Seconds())
				if time.Now().Sub(session.lastUse).Seconds() < wc.sessionTimeout {
					return session
				}
				log.Println("session expired, it was cleared")
				// session expired
				session.clear()
				return session
			}
		}

		// we ignore mismatched session ids, let's just create one
		session := newSession()
		wc.sessionManager.Add(session)
		return session
	}

	// sessions are not used...
	return nil
}
