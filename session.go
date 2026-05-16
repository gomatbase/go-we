// Copyright 2023-2026 GOM. All rights reserved.
// Since 20/10/2023 By GOM
// Licensed under MIT License

package we

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session management constants
const (
	// DefaultSessionTimeout Default duration of an idle/active session
	DefaultSessionTimeout = time.Hour
	// DefaultCookieName default cookie name set with the session id
	DefaultCookieName = "weSessionId"
	// DefaultPurgeInterval default session purge interval
	DefaultPurgeInterval = time.Minute
	// DefaultPurgeTimeout default timeout for purge operations
	DefaultPurgeTimeout = 10 * time.Second
)

// Session status constants
const (
	// SessionStatusNew indicates a newly created session
	SessionStatusNew uint = 0
	// SessionStatusExisting indicates an existing session retrieved from storage
	SessionStatusExisting uint = 1
)

// TODO: review session lifecycle and purging strategy. For example, instead of just a background thread that periodically
//  purges expired sessions support for immediate session expiration (logout) must be contemplated as well as a better
//  way to handle attribute deletion.

// Session interface provides methods for managing session attributes
type Session interface {
	// Get returns the value of an attribute stored in the session
	Get(key string) any
	// Set stores an attribute in the session
	Set(key string, value any)
	// Delete removes an attribute from the session
	Delete(key string)
	// Clear removes all attributes from the session
	Clear()
}

// SessionObject is the internal implementation of a session associated to a request (either the request comes with
// a session identifier or it is created for the request)
type SessionObject struct {
	// Status indicates if the Session has just been created (SessionStatusNew) or if it's an existing one (SessionStatusExisting)
	Status uint

	// Timestamp of last Session use
	LastUse time.Time

	// Unique Session id
	Id string

	// Payloads stored in the Session. Retrieval and use of context payloads are implementation specific.
	Attributes map[string]any
}

// Get returns the value of an attribute stored in the session
func (s *SessionObject) Get(key string) any {
	return s.Attributes[key]
}

// Set stores an attribute in the session
func (s *SessionObject) Set(key string, value any) {
	s.Attributes[key] = value
}

// Delete removes an attribute from the session
func (s *SessionObject) Delete(key string) {
	delete(s.Attributes, key)
}

// Clear removes all attributes from the session
func (s *SessionObject) Clear() {
	s.Attributes = make(map[string]any)
}

// SessionManager manages a Session life-cycle
type SessionManager interface {
	// GetHttpSession gets an existing http session from storage. Non-existing, expired or mismatched session-ids should
	// result in a new session and set in the response
	GetHttpSession(w http.ResponseWriter, r *http.Request) Session
}

// SessionStorage interface for a session storage service
type SessionStorage interface {
	// Get retrieves a session by its session id. nil if none is found
	Get(ctx context.Context, sessionId string) *SessionObject
	// Put stores/updates a session object, returns the existing object if updating or nil if new
	Put(ctx context.Context, session *SessionObject) *SessionObject
	// Delete deletes a session object referenced by its id. Return nil if no session is deleted.
	Delete(ctx context.Context, sessionId string) *SessionObject
	// PurgeOlderThan deletes from storage all sessions older than <age>
	PurgeOlderThan(ctx context.Context, age time.Duration)
}

// SessionManagerConfiguration Configuration settings for the default session manager
type SessionManagerConfiguration struct {
	// Allows providing a custom session storage. When nil the session manager will use the inMemory session storage
	Storage SessionStorage
	// The maximum duration of an idle/active session
	SessionTimeout time.Duration
	// Boolean setting the expiration type to use. If false, the timeout of a session is refreshed
	// after each access, if true a new session has a fixed duration, regardless if it's idle or not.
	StaticSessionLifespan bool
	// The cookie name to be used when setting it in the browser. Defaults to "weSessionId"
	CookieName string
	// Interval at which purging process checks for expired sessions and cleans them from storage
	SessionPurgingInterval time.Duration
	// Timeout for each purge operation. Defaults to DefaultPurgeTimeout (10 seconds)
	SessionPurgeTimeout time.Duration

	// Cookie security and scoping attributes
	// CookieHttpOnly prevents JavaScript access to the cookie (XSS protection).
	// When not explicitly set and using default configuration, defaults to true for security.
	// Set to false only if you need JavaScript cookie access.
	CookieHttpOnly *bool
	// CookieSecure restricts cookie to HTTPS only. Defaults to false to allow HTTP in development.
	// Should be set to true in production.
	CookieSecure bool
	// CookieSameSite controls cross-site cookie behavior for CSRF protection.
	// Defaults to http.SameSiteLaxMode. Use http.SameSiteStrictMode for stricter protection.
	CookieSameSite http.SameSite
	// CookiePath restricts cookie to specific path. Defaults to "/".
	CookiePath string
	// CookieDomain restricts cookie to specific domain. Defaults to "" (current domain).
	CookieDomain string
	// CookieMaxAge sets Max-Age attribute in seconds. 0 means session cookie (browser default).
	// Negative values delete the cookie immediately. Defaults to 0.
	CookieMaxAge int
	// CookiePartitioned enables partitioned cookies for third-party contexts (CHIPS). Defaults to false.
	CookiePartitioned bool
}

// sessionManager a SessionManager implementation with background thread cleaning stale sessions
type sessionManager struct {
	fixedLifespan bool
	timeout       time.Duration
	purgeTimeout  time.Duration
	storage       SessionStorage
	cookieName    string

	// Cookie configuration
	cookieHttpOnly    bool
	cookieSecure      bool
	cookieSameSite    http.SameSite
	cookiePath        string
	cookieDomain      string
	cookieMaxAge      int
	cookiePartitioned bool

	storageMutex sync.Mutex
}

func (sm *sessionManager) GetHttpSession(w http.ResponseWriter, r *http.Request) Session {
	var session *SessionObject
	sessionId, cookieFetchError := r.Cookie(sm.cookieName)
	// only http.ErrNoCookie is possible.
	if cookieFetchError == nil {
		sm.storageMutex.Lock()
		if session = sm.storage.Get(r.Context(), sessionId.Value); session != nil {
			if session.LastUse.Add(sm.timeout).Before(time.Now()) {
				sm.storage.Delete(r.Context(), session.Id)
				session = nil
			} else {
				// Update LastUse for rolling sessions (non-fixed lifespan)
				if !sm.fixedLifespan {
					session.LastUse = time.Now()
				}
				session.Status = SessionStatusExisting
			}
		}
		sm.storageMutex.Unlock()
	}

	if session == nil {
		sm.storageMutex.Lock()
		session = &SessionObject{
			Status:     SessionStatusNew,
			LastUse:    time.Now(),
			Id:         uuid.New().String(),
			Attributes: make(map[string]any),
		}
		sm.storage.Put(r.Context(), session)
		sm.storageMutex.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:        sm.cookieName,
			Value:       session.Id,
			Path:        sm.cookiePath,
			Domain:      sm.cookieDomain,
			MaxAge:      sm.cookieMaxAge,
			Secure:      sm.cookieSecure,
			HttpOnly:    sm.cookieHttpOnly,
			SameSite:    sm.cookieSameSite,
			Partitioned: sm.cookiePartitioned,
		})
	}

	return session
}

func (sm *sessionManager) purgeSessions() {
	ctx, cancel := context.WithTimeout(context.Background(), sm.purgeTimeout)
	defer cancel()
	defer sm.storageMutex.Unlock()
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Failed to purge old sessions: panic recovered: %v\n", r)
		}
	}()

	sm.storageMutex.Lock()
	sm.storage.PurgeOlderThan(ctx, sm.timeout)

	// Check if context timed out
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("Failed to purge old sessions: timeout exceeded")
	}
}

func (sm *sessionManager) purgeLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)

	for {
		<-ticker.C
		sm.purgeSessions()
	}
}

// inMemorySessionStorage SessionStorage implementation for inMemory storage.
type inMemorySessionStorage struct {
	sessions map[string]*SessionObject
}

func (imss *inMemorySessionStorage) PurgeOlderThan(_ context.Context, age time.Duration) {
	for id, session := range imss.sessions {
		if session.LastUse.Add(age).Before(time.Now()) {
			delete(imss.sessions, id)
		}
	}
}

func (imss *inMemorySessionStorage) Put(_ context.Context, session *SessionObject) *SessionObject {
	existingSession, found := imss.sessions[session.Id]
	imss.sessions[session.Id] = session
	if found {
		return existingSession
	}
	return nil
}

func (imss *inMemorySessionStorage) Delete(_ context.Context, sessionId string) *SessionObject {
	existingSession := imss.sessions[sessionId]
	delete(imss.sessions, sessionId)
	return existingSession
}

func (imss *inMemorySessionStorage) Get(_ context.Context, sessionId string) *SessionObject {
	return imss.sessions[sessionId]
}

// SessionManagerBuilder interface for building a SessionManager with fluent configuration
type SessionManagerBuilder interface {
	// Storage sets a custom session storage. If not set, an in-memory session storage is used.
	Storage(storage SessionStorage) SessionManagerBuilder
	// SessionTimeout sets the maximum duration of an idle/active session.
	// If not set or 0, defaults to DefaultSessionTimeout (1 hour).
	SessionTimeout(timeout time.Duration) SessionManagerBuilder
	// StaticSessionLifespan sets the expiration type. If false (default), the timeout of a session
	// is refreshed after each access. If true, a new session has a fixed duration.
	StaticSessionLifespan(static bool) SessionManagerBuilder
	// CookieName sets the cookie name to be used when setting it in the browser.
	// If not set or empty, defaults to DefaultCookieName ("weSessionId").
	CookieName(name string) SessionManagerBuilder
	// SessionPurgingInterval sets the interval at which purging process checks for expired sessions.
	// If not set or 0, defaults to DefaultPurgeInterval (1 minute).
	SessionPurgingInterval(interval time.Duration) SessionManagerBuilder
	// SessionPurgeTimeout sets the timeout for each purge operation.
	// If not set or 0, defaults to DefaultPurgeTimeout (10 seconds).
	SessionPurgeTimeout(timeout time.Duration) SessionManagerBuilder
	// CookieHttpOnly sets whether JavaScript can access the cookie (XSS protection).
	// If not set, defaults to true for security. Set to false only if you need JavaScript cookie access.
	CookieHttpOnly(httpOnly bool) SessionManagerBuilder
	// CookieSecure restricts cookie to HTTPS only. Defaults to false to allow HTTP in development.
	// Should be set to true in production.
	CookieSecure(secure bool) SessionManagerBuilder
	// CookieSameSite controls cross-site cookie behavior for CSRF protection.
	// If not set or 0, defaults to http.SameSiteLaxMode. Use http.SameSiteStrictMode for stricter protection.
	CookieSameSite(sameSite http.SameSite) SessionManagerBuilder
	// CookiePath restricts cookie to specific path. If not set or empty, defaults to "/".
	CookiePath(path string) SessionManagerBuilder
	// CookieDomain restricts cookie to specific domain. If not set or empty, defaults to "" (current domain).
	CookieDomain(domain string) SessionManagerBuilder
	// CookieMaxAge sets Max-Age attribute in seconds. 0 means session cookie (browser default).
	// Negative values delete the cookie immediately. Defaults to 0.
	CookieMaxAge(maxAge int) SessionManagerBuilder
	// CookiePartitioned enables partitioned cookies for third-party contexts (CHIPS). Defaults to false.
	CookiePartitioned(partitioned bool) SessionManagerBuilder
	// Build creates and returns the configured SessionManager.
	// This method starts the background purge loop as a goroutine.
	Build() SessionManager
}

// sessionManagerBuilder implementation of SessionManagerBuilder interface
type sessionManagerBuilder struct {
	*sessionManager
	sessionPurgingInterval time.Duration
}

// Storage sets a custom session storage. If not set, an in-memory session storage is used.
func (b *sessionManagerBuilder) Storage(storage SessionStorage) SessionManagerBuilder {
	b.storage = storage
	return b
}

// SessionTimeout sets the maximum duration of an idle/active session.
// If not set, defaults to DefaultSessionTimeout (1 hour). Panics if attempting to set a non-positive duration.
func (b *sessionManagerBuilder) SessionTimeout(timeout time.Duration) SessionManagerBuilder {
	if timeout <= 0 {
		panic("Session timeout must be greater than 0")
	}
	b.timeout = timeout
	return b
}

// StaticSessionLifespan sets the expiration type. If false (default), the timeout of a session
// is refreshed after each access. If true, a new session has a fixed duration.
func (b *sessionManagerBuilder) StaticSessionLifespan(static bool) SessionManagerBuilder {
	b.fixedLifespan = static
	return b
}

// CookieName sets the cookie name to be used when setting it in the browser.
// If not set, defaults to DefaultCookieName ("weSessionId"). Panics if attempting to set an empty cookie name.
func (b *sessionManagerBuilder) CookieName(name string) SessionManagerBuilder {
	if len(name) == 0 {
		panic("Cookie name cannot be empty")
	}
	b.cookieName = name
	return b
}

// SessionPurgingInterval sets the interval at which purging process checks for expired sessions.
// If not set, defaults to DefaultPurgeInterval (1 minute). Panics if attempting to set a non-positive duration.
func (b *sessionManagerBuilder) SessionPurgingInterval(interval time.Duration) SessionManagerBuilder {
	if interval <= 0 {
		panic("Session purging interval must be greater than 0")
	}
	b.sessionPurgingInterval = interval
	return b
}

// SessionPurgeTimeout sets the timeout for each purge operation.
// If not set, defaults to DefaultPurgeTimeout (10 seconds). Panics if attempting to set a non-positive duration.
func (b *sessionManagerBuilder) SessionPurgeTimeout(timeout time.Duration) SessionManagerBuilder {
	b.purgeTimeout = timeout
	return b
}

// CookieHttpOnly sets whether JavaScript can access the cookie (XSS protection).
// If not set, defaults to true for security. Set to false only if you need JavaScript cookie access.
func (b *sessionManagerBuilder) CookieHttpOnly(httpOnly bool) SessionManagerBuilder {
	b.cookieHttpOnly = httpOnly
	return b
}

// CookieSecure restricts cookie to HTTPS only. Defaults to false to allow HTTP in development.
// Should be set to true in production.
func (b *sessionManagerBuilder) CookieSecure(secure bool) SessionManagerBuilder {
	b.cookieSecure = secure
	return b
}

// CookieSameSite controls cross-site cookie behavior for CSRF protection.
// If not set or 0, defaults to http.SameSiteLaxMode. Use http.SameSiteStrictMode for stricter protection.
func (b *sessionManagerBuilder) CookieSameSite(sameSite http.SameSite) SessionManagerBuilder {
	b.cookieSameSite = sameSite
	return b
}

// CookiePath restricts cookie to specific path. If not set or empty, defaults to "/".
func (b *sessionManagerBuilder) CookiePath(path string) SessionManagerBuilder {
	b.cookiePath = path
	return b
}

// CookieDomain restricts cookie to specific domain. If not set or empty, defaults to "" (current domain).
func (b *sessionManagerBuilder) CookieDomain(domain string) SessionManagerBuilder {
	b.cookieDomain = domain
	return b
}

// CookieMaxAge sets Max-Age attribute in seconds. 0 means session cookie (browser default).
// Negative values delete the cookie immediately. Defaults to 0.
func (b *sessionManagerBuilder) CookieMaxAge(maxAge int) SessionManagerBuilder {
	b.cookieMaxAge = maxAge
	return b
}

// CookiePartitioned enables partitioned cookies for third-party contexts (CHIPS). Defaults to false.
func (b *sessionManagerBuilder) CookiePartitioned(partitioned bool) SessionManagerBuilder {
	b.cookiePartitioned = partitioned
	return b
}

// Build creates and returns the configured SessionManager with all defaults applied.
// This method starts the background purge loop as a goroutine.
func (b *sessionManagerBuilder) Build() SessionManager {
	// Apply defaults for storage
	if b.storage == nil {
		b.storage = &inMemorySessionStorage{sessions: make(map[string]*SessionObject)}
	}

	go b.purgeLoop(b.sessionPurgingInterval)

	return b.sessionManager
}

// DefaultSessionManager returns a SessionManagerBuilder with default configuration.
// Use the builder methods to customize the session manager, then call Build() to create it.
//
// Example with defaults:
//
//	sessionManager := we.DefaultSessionManager().Build()
//	engine.SetSessionManager(sessionManager)
//
// Example with custom configuration:
//
//	sessionManager := we.DefaultSessionManager().
//	    SessionTimeout(2 * time.Hour).
//	    CookieName("myapp_session").
//	    CookieSecure(true).
//	    CookieSameSite(http.SameSiteStrictMode).
//	    Build()
//	engine.SetSessionManager(sessionManager)
//
// Example disabling HttpOnly (not recommended):
//
//	sessionManager := we.DefaultSessionManager().
//	    CookieHttpOnly(false).
//	    Build()
func DefaultSessionManager() SessionManagerBuilder {
	return &sessionManagerBuilder{
		sessionManager: &sessionManager{
			timeout:        DefaultSessionTimeout,
			cookieName:     DefaultCookieName,
			purgeTimeout:   DefaultPurgeTimeout,
			cookieHttpOnly: true,
			cookieSameSite: http.SameSiteLaxMode,
			cookiePath:     "/",
		},
		sessionPurgingInterval: DefaultPurgeInterval,
	}
}
