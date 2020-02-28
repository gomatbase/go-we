// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"github.com/google/uuid"
	"time"
)

//baby
const (
	//soso
	NEW = iota
	EXISTING =  iota

	DEFAULT_SESSION_TIMEOUT = float64(3600)
)

//whassup
type Session struct {
	Status    uint
	lastUse   time.Time
	SessionId string

    Context   map[string]interface{}
}

func (s *Session) clear() {
	s.Status = NEW
	s.lastUse = time.Now()
	s.Context = make(map[string]interface{})
}

func newSession() *Session {
	session := new(Session)
	session.Status = NEW
	session.lastUse = time.Now()
	session.SessionId = uuid.New().String()
	session.Context = make(map[string]interface{})

	return session
}

type SessionManager interface {
	Get(sessionId string) *Session
	Add(session *Session) *Session
}

func NewInMemorySessionManager() *InMemorySessionManager {
	sessionManager := new(InMemorySessionManager)
	sessionManager.sessions = make(map[string]*Session)

	return sessionManager
}

type InMemorySessionManager struct {
	sessions map[string]*Session
}

func (sm *InMemorySessionManager)Get(sessionId string) *Session {
	if session, found := sm.sessions[sessionId]; found {
		return session
	}
	return nil
}

func (sm *InMemorySessionManager)Add(newSession *Session) *Session {
	session, found := sm.sessions[newSession.SessionId]
	sm.sessions[newSession.SessionId] = newSession
	if found {
		return session
	}
	return nil
}

