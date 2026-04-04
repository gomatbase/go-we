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

			if session.Status != SessionStatusNew {
				t.Errorf("Expected new session, got status %d", session.Status)
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

	if session1.Status != SessionStatusNew {
		t.Fatalf("Expected new session, got status %d", session1.Status)
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

	if session2.Status != SessionStatusExisting {
		t.Errorf("Expected existing session, got status %d", session2.Status)
	}

	if session2.Id != session1.Id {
		t.Errorf("Session ID mismatch: got %q, want %q", session2.Id, session1.Id)
	}

	// Verify no new cookie was set for existing session
	cookies2 := w2.Result().Cookies()
	if len(cookies2) != 0 {
		t.Errorf("Expected no new cookies for existing session, got %d", len(cookies2))
	}
}

// Helper function to create *bool
func boolPtr(b bool) *bool {
	return &b
}
