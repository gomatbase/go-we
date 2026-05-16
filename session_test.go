// Copyright 2026 GOM. All rights reserved.
// Since 04/04/2026 By GOM
// Licensed under MIT License

package we

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieAttributes(t *testing.T) {
	tests := []struct {
		name    string
		builder func() SessionManagerBuilder
		want    struct {
			httpOnly    bool
			secure      bool
			sameSite    http.SameSite
			path        string
			domain      string
			maxAge      int
			partitioned bool
		}
	}{
		{
			name:    "Default configuration (secure by default)",
			builder: func() SessionManagerBuilder { return DefaultSessionManager() },
			want: struct {
				httpOnly    bool
				secure      bool
				sameSite    http.SameSite
				path        string
				domain      string
				maxAge      int
				partitioned bool
			}{
				httpOnly:    true,                 // Default to true for security
				secure:      false,                // Default to false for dev compatibility
				sameSite:    http.SameSiteLaxMode, // Default
				path:        "/",                  // Default
				domain:      "",                   // Default (current domain)
				maxAge:      0,                    // Default (session cookie)
				partitioned: false,                // Default
			},
		},
		{
			name: "Production secure configuration",
			builder: func() SessionManagerBuilder {
				return DefaultSessionManager().
					CookieSecure(true).
					CookieSameSite(http.SameSiteStrictMode).
					CookiePath("/app").
					CookieDomain("example.com")
			},
			want: struct {
				httpOnly    bool
				secure      bool
				sameSite    http.SameSite
				path        string
				domain      string
				maxAge      int
				partitioned bool
			}{
				httpOnly:    true,                    // Still defaults to true
				secure:      true,                    // Explicitly set
				sameSite:    http.SameSiteStrictMode, // Explicitly set
				path:        "/app",                  // Explicitly set
				domain:      "example.com",           // Explicitly set
				maxAge:      0,                       // Default
				partitioned: false,                   // Default
			},
		},
		{
			name: "Explicitly disable HttpOnly (not recommended)",
			builder: func() SessionManagerBuilder {
				return DefaultSessionManager().CookieHttpOnly(false)
			},
			want: struct {
				httpOnly    bool
				secure      bool
				sameSite    http.SameSite
				path        string
				domain      string
				maxAge      int
				partitioned bool
			}{
				httpOnly:    false,                // Explicitly disabled
				secure:      false,                // Default
				sameSite:    http.SameSiteLaxMode, // Default
				path:        "/",                  // Default
				domain:      "",                   // Default
				maxAge:      0,                    // Default
				partitioned: false,                // Default
			},
		},
		{
			name: "Full custom configuration",
			builder: func() SessionManagerBuilder {
				return DefaultSessionManager().
					CookieHttpOnly(true).
					CookieSecure(true).
					CookieSameSite(http.SameSiteNoneMode).
					CookiePath("/api").
					CookieDomain("api.example.com").
					CookieMaxAge(3600).
					CookiePartitioned(true)
			},
			want: struct {
				httpOnly    bool
				secure      bool
				sameSite    http.SameSite
				path        string
				domain      string
				maxAge      int
				partitioned bool
			}{
				httpOnly:    true,
				secure:      true,
				sameSite:    http.SameSiteNoneMode,
				path:        "/api",
				domain:      "api.example.com",
				maxAge:      3600,
				partitioned: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create session manager with test configuration
			sessionManager := tt.builder().Build()

			// Create test request and response recorder
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			// Get session (should create new session and set cookie)
			session := sessionManager.GetHttpSession(w, req)

			// Verify session was created
			if session == nil {
				t.Fatal("Expected session to be created")
			}

			sessionObj := session.(*SessionObject)
			if sessionObj.Status != SessionStatusNew {
				t.Errorf("Expected new session, got status %d", sessionObj.Status)
			}

			// Get the Set-Cookie header
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("Expected 1 cookie, got %d", len(cookies))
			}

			cookie := cookies[0]

			// Verify cookie attributes
			if cookie.HttpOnly != tt.want.httpOnly {
				t.Errorf("HttpOnly: got %v, want %v", cookie.HttpOnly, tt.want.httpOnly)
			}

			if cookie.Secure != tt.want.secure {
				t.Errorf("Secure: got %v, want %v", cookie.Secure, tt.want.secure)
			}

			if cookie.SameSite != tt.want.sameSite {
				t.Errorf("SameSite: got %v, want %v", cookie.SameSite, tt.want.sameSite)
			}

			if cookie.Path != tt.want.path {
				t.Errorf("Path: got %q, want %q", cookie.Path, tt.want.path)
			}

			if cookie.Domain != tt.want.domain {
				t.Errorf("Domain: got %q, want %q", cookie.Domain, tt.want.domain)
			}

			if cookie.MaxAge != tt.want.maxAge {
				t.Errorf("MaxAge: got %d, want %d", cookie.MaxAge, tt.want.maxAge)
			}

			if cookie.Partitioned != tt.want.partitioned {
				t.Errorf("Partitioned: got %v, want %v", cookie.Partitioned, tt.want.partitioned)
			}

			// Verify cookie name (all tests use default name)
			if cookie.Name != DefaultCookieName {
				t.Errorf("Cookie name: got %q, want %q", cookie.Name, DefaultCookieName)
			}

			if cookie.Value == "" {
				t.Error("Cookie value should not be empty")
			}
		})
	}
}

func TestSessionCookieAttributesExistingSession(t *testing.T) {
	// Create session manager with custom config using builder
	sessionManager := DefaultSessionManager().
		CookieHttpOnly(false).
		CookieSecure(true).
		CookieSameSite(http.SameSiteStrictMode).
		CookiePath("/app").
		SessionTimeout(time.Hour).
		StaticSessionLifespan(false). // rolling session
		Build()

	// Create initial session
	req1 := httptest.NewRequest("GET", "/app/test", nil)
	w1 := httptest.NewRecorder()
	session1 := sessionManager.GetHttpSession(w1, req1)
	sessionObj1 := session1.(*SessionObject)

	if sessionObj1.Status != SessionStatusNew {
		t.Fatalf("Expected new session, got status %d", sessionObj1.Status)
	}

	// Get the session ID from cookie
	cookies := w1.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}
	sessionID := cookies[0].Value

	// Create second request with the session cookie
	req2 := httptest.NewRequest("GET", "/app/test2", nil)
	req2.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: sessionID,
	})
	w2 := httptest.NewRecorder()

	// Get existing session (should not set cookie again)
	session2 := sessionManager.GetHttpSession(w2, req2)
	sessionObj2 := session2.(*SessionObject)

	if sessionObj2.Status != SessionStatusExisting {
		t.Errorf("Expected existing session, got status %d", sessionObj2.Status)
	}

	if sessionObj2.Id != sessionObj1.Id {
		t.Errorf("Session ID mismatch: got %q, want %q", sessionObj2.Id, sessionObj1.Id)
	}

	// Verify no new cookie was set for existing session
	cookies2 := w2.Result().Cookies()
	if len(cookies2) != 0 {
		t.Errorf("Expected no new cookies for existing session, got %d", len(cookies2))
	}
}

func TestSessionManagerBuilderMethods(t *testing.T) {
	t.Run("Test all builder methods", func(t *testing.T) {
		manager := DefaultSessionManager().
			SessionTimeout(45 * time.Minute).
			CookieName("CUSTOM_SESSION").
			SessionPurgingInterval(10 * time.Minute).
			SessionPurgeTimeout(5 * time.Second).
			CookieHttpOnly(false).
			CookieSecure(true).
			CookieSameSite(http.SameSiteNoneMode).
			CookiePath("/api").
			CookieDomain("example.com").
			CookieMaxAge(3600).
			CookiePartitioned(true).
			Build()

		// Verify manager was created
		if manager == nil {
			t.Fatal("Expected manager to be created")
		}

		// Create test request and verify session with custom settings
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()

		session := manager.GetHttpSession(w, req)
		if session == nil {
			t.Fatal("Expected session to be created")
		}

		// Verify cookie with custom settings
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("Expected 1 cookie, got %d", len(cookies))
		}

		cookie := cookies[0]
		if cookie.Name != "CUSTOM_SESSION" {
			t.Errorf("Expected cookie name CUSTOM_SESSION, got %s", cookie.Name)
		}
		if cookie.HttpOnly != false {
			t.Error("Expected HttpOnly to be false")
		}
		if cookie.Secure != true {
			t.Error("Expected Secure to be true")
		}
		if cookie.SameSite != http.SameSiteNoneMode {
			t.Errorf("Expected SameSite None, got %v", cookie.SameSite)
		}
		if cookie.Path != "/api" {
			t.Errorf("Expected path /api, got %s", cookie.Path)
		}
		if cookie.Domain != "example.com" {
			t.Errorf("Expected domain example.com, got %s", cookie.Domain)
		}
		if cookie.MaxAge != 3600 {
			t.Errorf("Expected MaxAge 3600, got %d", cookie.MaxAge)
		}
		if cookie.Partitioned != true {
			t.Error("Expected Partitioned to be true")
		}
	})
}

func TestSessionStorage(t *testing.T) {
	t.Run("Delete session from storage", func(t *testing.T) {
		manager := DefaultSessionManager().
			SessionTimeout(1 * time.Hour).
			Build().(*sessionManager)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// Create session
		session := manager.GetHttpSession(w, req)
		sessionObj := session.(*SessionObject)
		sessionId := sessionObj.Id

		// Verify session exists
		if manager.storage.Get(nil, sessionId) == nil {
			t.Fatal("Session should exist in storage")
		}

		// Delete session
		deleted := manager.storage.Delete(nil, sessionId)
		if deleted == nil {
			t.Error("Delete should return the deleted session")
		}
		if deleted.Id != sessionId {
			t.Errorf("Deleted session ID mismatch: expected %s, got %s", sessionId, deleted.Id)
		}

		// Verify session no longer exists
		if manager.storage.Get(nil, sessionId) != nil {
			t.Error("Session should not exist after deletion")
		}
	})

	t.Run("Put replaces existing session", func(t *testing.T) {
		manager := DefaultSessionManager().Build().(*sessionManager)

		// Create initial session
		session1 := &SessionObject{
			Id:         "test-session-1",
			LastUse:    time.Now(),
			Attributes: map[string]interface{}{"key": "value1"},
		}
		manager.storage.Put(nil, session1)

		// Put new session with same ID
		session2 := &SessionObject{
			Id:         "test-session-1",
			LastUse:    time.Now(),
			Attributes: map[string]interface{}{"key": "value2"},
		}
		existing := manager.storage.Put(nil, session2)

		// Put should return the existing session
		if existing == nil {
			t.Fatal("Put should return existing session when replacing")
		}
		if existing.Attributes["key"] != "value1" {
			t.Errorf("Expected existing session with value1, got %v", existing.Attributes["key"])
		}

		// New session should be in storage
		retrieved := manager.storage.Get(nil, "test-session-1")
		if retrieved.Attributes["key"] != "value2" {
			t.Errorf("Expected new session with value2, got %v", retrieved.Attributes["key"])
		}
	})

	t.Run("PurgeOlderThan removes expired sessions", func(t *testing.T) {
		manager := DefaultSessionManager().
			SessionTimeout(100 * time.Millisecond).
			Build().(*sessionManager)

		// Create old session
		oldSession := &SessionObject{
			Id:         "old-session",
			LastUse:    time.Now().Add(-200 * time.Millisecond),
			Attributes: map[string]interface{}{},
		}
		manager.storage.Put(nil, oldSession)

		// Create recent session
		recentSession := &SessionObject{
			Id:         "recent-session",
			LastUse:    time.Now(),
			Attributes: map[string]interface{}{},
		}
		manager.storage.Put(nil, recentSession)

		// Purge sessions older than 150ms
		manager.storage.PurgeOlderThan(nil, 150*time.Millisecond)

		// Old session should be deleted
		if manager.storage.Get(nil, "old-session") != nil {
			t.Error("Old session should have been purged")
		}

		// Recent session should still exist
		if manager.storage.Get(nil, "recent-session") == nil {
			t.Error("Recent session should not have been purged")
		}
	})

	t.Run("Storage getter returns configured storage", func(t *testing.T) {
		customStorage := &inMemorySessionStorage{
			sessions: make(map[string]*SessionObject),
		}

		manager := DefaultSessionManager().
			Storage(customStorage).
			Build().(*sessionManager)

		if manager.storage != customStorage {
			t.Error("Storage() should return the configured custom storage")
		}
	})
}

func TestSessionBuilderValidation(t *testing.T) {
	t.Run("SessionTimeout panics on zero duration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when setting zero session timeout")
			}
		}()
		DefaultSessionManager().SessionTimeout(0)
	})

	t.Run("SessionTimeout panics on negative duration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when setting negative session timeout")
			}
		}()
		DefaultSessionManager().SessionTimeout(-1 * time.Hour)
	})

	t.Run("CookieName panics on empty string", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when setting empty cookie name")
			}
		}()
		DefaultSessionManager().CookieName("")
	})

	t.Run("SessionPurgingInterval panics on zero duration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when setting zero purging interval")
			}
		}()
		DefaultSessionManager().SessionPurgingInterval(0)
	})

	t.Run("SessionPurgingInterval panics on negative duration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when setting negative purging interval")
			}
		}()
		DefaultSessionManager().SessionPurgingInterval(-1 * time.Minute)
	})
}

func TestSessionPurgeLoop(t *testing.T) {
	t.Run("purgeSessions is called and handles old sessions", func(t *testing.T) {
		manager := DefaultSessionManager().
			SessionTimeout(50 * time.Millisecond).
			Build().(*sessionManager)

		// Create an old session
		oldSession := &SessionObject{
			Id:         "old-test-session",
			LastUse:    time.Now().Add(-100 * time.Millisecond),
			Attributes: map[string]interface{}{},
		}
		manager.storage.Put(nil, oldSession)

		// Manually call purgeSessions (normally called by purgeLoop)
		manager.purgeSessions()

		// Verify old session was purged
		if manager.storage.Get(nil, "old-test-session") != nil {
			t.Error("Old session should have been purged by purgeSessions()")
		}
	})
}
