// Copyright 2023 GOM. All rights reserved.
// Since 20/10/2023 By GOM
// Licensed under MIT License

package we

import (
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
)

// Session object associated to a request (either the request comes with a Session identifier or it is created for
// the request
type Session struct {
	// If the Session has just been created or if it's an existing one
	Status uint

	// Timestamp of last Session use
	LastUse time.Time

	// Unique Session id
	Id string

	// Payloads stored in the Session. Retrieval and use of context payloads are implementation specific.
	Attributes map[string]interface{}
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
	Get(sessionId string) *Session
	// Put stores/updates a session object, returns the existing object if updating or nil if new
	Put(session *Session) *Session
	// Delete deletes a session object referenced by its id. Return nil if no session is deleted.
	Delete(sessionId string) *Session
	// PurgeOlderThan deletes from storage all sessions older than <age>
	PurgeOlderThan(age time.Duration)
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
}

// sessionManager a SessionManager implementation with background thread cleaning stale sessions
type sessionManager struct {
	fixedLifespan bool
	timeout       time.Duration
	storage       SessionStorage
	cookieName    string

	storageMutex sync.Mutex
}

func (sm *sessionManager) GetHttpSession(w http.ResponseWriter, r *http.Request) *Session {
	var session *Session
	sessionId, cookieFetchError := r.Cookie(sm.cookieName)
	if cookieFetchError != http.ErrNoCookie {
		sm.storageMutex.Lock()
		if session = sm.storage.Get(sessionId.Value); session != nil {
			if session.LastUse.Add(sm.timeout).Before(time.Now()) {
				sm.storage.Delete(session.Id)
				session = nil
			}
		}
		sm.storageMutex.Unlock()
	}

	if session == nil {
		sm.storageMutex.Lock()
		session = &Session{
			LastUse:    time.Time{},
			Id:         uuid.New().String(),
			Attributes: make(map[string]interface{}),
		}
		sm.storage.Put(session)
		sm.storageMutex.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sm.cookieName, Value: session.Id, Path: "/"})
	}

	return session
}

func (sm *sessionManager) purgeLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)

	for {
		<-ticker.C
		sm.storageMutex.Lock()
		sm.storage.PurgeOlderThan(sm.timeout)
		sm.storageMutex.Unlock()
	}
}

// inMemorySessionStorage SessionStorage implementation for inMemory storage.
type inMemorySessionStorage struct {
	sessions map[string]*Session
}

func (imss *inMemorySessionStorage) PurgeOlderThan(age time.Duration) {
	for id, session := range imss.sessions {
		if session.LastUse.Add(age).Before(time.Now()) {
			delete(imss.sessions, id)
		}
	}
}

func (imss *inMemorySessionStorage) Put(session *Session) *Session {
	existingSession, found := imss.sessions[session.Id]
	imss.sessions[session.Id] = session
	if found {
		return existingSession
	}
	return nil
}

func (imss *inMemorySessionStorage) Delete(sessionId string) *Session {
	existingSession := imss.sessions[sessionId]
	delete(imss.sessions, sessionId)
	return existingSession
}

func (imss *inMemorySessionStorage) Get(sessionId string) *Session {
	return imss.sessions[sessionId]
}

// DefaultSessionManager provides a default in-memory Session manager
func DefaultSessionManager(configuration SessionManagerConfiguration) SessionManager {
	sm := &sessionManager{
		timeout:       configuration.SessionTimeout,
		storage:       configuration.Storage,
		fixedLifespan: configuration.StaticSessionLifespan,
		cookieName:    configuration.CookieName,
	}

	if sm.timeout == 0 {
		sm.timeout = DefaultSessionTimeout
	}

	if sm.storage == nil {
		sm.storage = &inMemorySessionStorage{sessions: make(map[string]*Session)}
	}

	if len(sm.cookieName) == 0 {
		sm.cookieName = DefaultCookieName
	}

	if configuration.SessionPurgingInterval == 0 {
		configuration.SessionPurgingInterval = DefaultPurgeInterval
	}

	go sm.purgeLoop(configuration.SessionPurgingInterval)

	return sm
}
