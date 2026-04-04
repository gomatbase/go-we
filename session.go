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

// Session object associated to a request (either the request comes with a Session identifier or it is created for
// the request
type Session struct {
	// Status indicates if the Session has just been created (SessionStatusNew) or if it's an existing one (SessionStatusExisting)
	Status uint

	// Timestamp of last Session use
	LastUse time.Time

	// Unique Session id
	Id string

	// Payloads stored in the Session. Retrieval and use of context payloads are implementation specific.
	Attributes map[string]any
}

// SessionManager manages a Session life-cycle
type SessionManager interface {
	// GetHttpSession gets an existing http session from storage. Non-existing, expired or mismatched session-ids should
	// result in a new session and set in the response
	GetHttpSession(w http.ResponseWriter, r *http.Request) *Session
}

// SessionStorage interface for a session storage service
type SessionStorage interface {
	// Get retrieves a session by its session id. nil if none is found
	Get(ctx context.Context, sessionId string) *Session
	// Put stores/updates a session object, returns the existing object if updating or nil if new
	Put(ctx context.Context, session *Session) *Session
	// Delete deletes a session object referenced by its id. Return nil if no session is deleted.
	Delete(ctx context.Context, sessionId string) *Session
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

func (sm *sessionManager) GetHttpSession(w http.ResponseWriter, r *http.Request) *Session {
	var session *Session
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
		session = &Session{
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
	sessions map[string]*Session
}

func (imss *inMemorySessionStorage) PurgeOlderThan(_ context.Context, age time.Duration) {
	for id, session := range imss.sessions {
		if session.LastUse.Add(age).Before(time.Now()) {
			delete(imss.sessions, id)
		}
	}
}

func (imss *inMemorySessionStorage) Put(_ context.Context, session *Session) *Session {
	existingSession, found := imss.sessions[session.Id]
	imss.sessions[session.Id] = session
	if found {
		return existingSession
	}
	return nil
}

func (imss *inMemorySessionStorage) Delete(_ context.Context, sessionId string) *Session {
	existingSession := imss.sessions[sessionId]
	delete(imss.sessions, sessionId)
	return existingSession
}

func (imss *inMemorySessionStorage) Get(_ context.Context, sessionId string) *Session {
	return imss.sessions[sessionId]
}

// DefaultSessionManager creates and returns a SessionManager with the provided configuration.
// If Storage is nil, an in-memory session storage is used.
// If SessionTimeout is 0, DefaultSessionTimeout (1 hour) is used.
// If CookieName is empty, DefaultCookieName ("weSessionId") is used.
// If SessionPurgingInterval is 0, DefaultPurgeInterval (1 minute) is used.
// If SessionPurgeTimeout is 0, DefaultPurgeTimeout (10 seconds) is used.
// If CookiePath is empty, defaults to "/".
// If CookieSameSite is 0, defaults to http.SameSiteLaxMode.
// If CookieHttpOnly is nil, defaults to true for security (prevents JavaScript access).
//
// Example with secure defaults:
//
//	sessionManager := we.DefaultSessionManager(we.SessionManagerConfiguration{
//	    SessionTimeout: time.Hour,
//	    CookieName: "myapp_session",
//	    StaticSessionLifespan: false, // rolling sessions
//	    // CookieHttpOnly defaults to true (secure by default)
//	    CookieSecure: true,           // HTTPS only (recommended for production)
//	    CookieSameSite: http.SameSiteStrictMode, // CSRF protection
//	})
//	engine.SetSessionManager(sessionManager)
//
// To explicitly disable HttpOnly (not recommended):
//
//	httpOnlyFalse := false
//	sessionManager := we.DefaultSessionManager(we.SessionManagerConfiguration{
//	    CookieHttpOnly: &httpOnlyFalse, // Explicitly disable (allows JavaScript access)
//	})
func DefaultSessionManager(configuration SessionManagerConfiguration) SessionManager {
	// Determine CookieHttpOnly value (defaults to true for security)
	cookieHttpOnly := true
	if configuration.CookieHttpOnly != nil {
		cookieHttpOnly = *configuration.CookieHttpOnly
	}

	sm := &sessionManager{
		timeout:           configuration.SessionTimeout,
		purgeTimeout:      configuration.SessionPurgeTimeout,
		storage:           configuration.Storage,
		fixedLifespan:     configuration.StaticSessionLifespan,
		cookieName:        configuration.CookieName,
		cookieHttpOnly:    cookieHttpOnly,
		cookieSecure:      configuration.CookieSecure,
		cookieSameSite:    configuration.CookieSameSite,
		cookiePath:        configuration.CookiePath,
		cookieDomain:      configuration.CookieDomain,
		cookieMaxAge:      configuration.CookieMaxAge,
		cookiePartitioned: configuration.CookiePartitioned,
	}

	if sm.timeout == 0 {
		sm.timeout = DefaultSessionTimeout
	}

	if sm.purgeTimeout == 0 {
		sm.purgeTimeout = DefaultPurgeTimeout
	}

	if sm.storage == nil {
		sm.storage = &inMemorySessionStorage{sessions: make(map[string]*Session)}
	}

	if len(sm.cookieName) == 0 {
		sm.cookieName = DefaultCookieName
	}

	if len(sm.cookiePath) == 0 {
		sm.cookiePath = "/"
	}

	if sm.cookieSameSite == 0 {
		sm.cookieSameSite = http.SameSiteLaxMode
	}

	if configuration.SessionPurgingInterval == 0 {
		configuration.SessionPurgingInterval = DefaultPurgeInterval
	}

	go sm.purgeLoop(configuration.SessionPurgingInterval)

	return sm
}
