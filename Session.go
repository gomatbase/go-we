// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"github.com/google/uuid"
	"time"
)

// Session management constants
const (
	// The session has been just created
	NEW = iota
	// The session is currently stored in the session manager
	EXISTING

	// Default session timeout (1 hour)
	DEFAULT_SESSION_TIMEOUT = float64(3600)
)

// Session object associated to a request (either the request comes with a session identifier or it is created for
// the request
type Session struct {
	// If the session has just been created or if it's an existing one
	Status    uint

	// Timestamp of last session use
	lastUse   time.Time

	// Unique session id
	SessionId string

	// Payloads stored in the session. Retrieval and use of context payloads are implementation specific.
    Context   map[string]interface{}
}

// Clears the session status, typically used when the session has been retrieved, but it has expired. Difference between
// clearing and creating a new session is just related to the session id, which is kept when the session is cleared
func (s *Session) clear() {
	s.Status = NEW
	s.lastUse = time.Now()
	s.Context = make(map[string]interface{})
}

// Creates a new session
func newSession() *Session {
	session := new(Session)
	session.Status = NEW
	session.lastUse = time.Now()
	session.SessionId = uuid.New().String()
	session.Context = make(map[string]interface{})

	return session
}

// A Session Manager is responsible to store and retrieve session objects.
type SessionManager interface {
	// Gets a session from the manager using the sessionId. It's expected to return th found session or nil if
	// no session exists with the provided session id.
	Get(sessionId string) *Session

	// Adds a session to the manager. It's not expected to raise errors, and if adding a new session with an existing
	// key, it's expected that the implementation will return the currently existing session. Should return nil for
	// new sessions (with unique key). Session id's should be unique and it should not be a common use case on of adding
	// sessions with an existing key.
	Add(session *Session) *Session
}

// Create a new in-memory session manager
func NewInMemorySessionManager() *InMemorySessionManager {
	sessionManager := new(InMemorySessionManager)
	sessionManager.sessions = make(map[string]*Session)

	return sessionManager
}

// InMemory Session Manager implementation, stores and maintains sessions in memory
type InMemorySessionManager struct {
	sessions map[string]*Session
}

// Gets a session from memory with the provided session id
func (sm *InMemorySessionManager) Get(sessionId string) *Session {
	if session, found := sm.sessions[sessionId]; found {
		return session
	}
	return nil
}

// Add a session to the manager. It allows adding a session with an existing key, in which case it will replace the
// current session and will return the existing session. If no sessions exist with the same key, nil is returned
func (sm *InMemorySessionManager) Add(newSession *Session) *Session {
	session, found := sm.sessions[newSession.SessionId]
	sm.sessions[newSession.SessionId] = newSession
	if found {
		return session
	}
	return nil
}

