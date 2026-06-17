// Copyright 2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package we_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	we "github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/test"
)

// --- Engine Builder Timeout Tests ---

func TestBuilderReadHeaderTimeout(t *testing.T) {
	t.Run("valid duration", func(t *testing.T) {
		engine := we.New().
			ReadHeaderTimeout(5*time.Second).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("zero duration is valid", func(t *testing.T) {
		engine := we.New().
			ReadHeaderTimeout(0).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("negative duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for negative read header timeout")
			}
		}()
		we.New().ReadHeaderTimeout(-1 * time.Second)
	})
}

func TestBuilderReadTimeout(t *testing.T) {
	t.Run("valid duration", func(t *testing.T) {
		engine := we.New().
			ReadTimeout(10*time.Second).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("zero duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for zero read timeout")
			}
		}()
		we.New().ReadTimeout(0)
	})

	t.Run("negative duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for negative read timeout")
			}
		}()
		we.New().ReadTimeout(-1 * time.Second)
	})
}

func TestBuilderWriteTimeout(t *testing.T) {
	t.Run("valid duration", func(t *testing.T) {
		engine := we.New().
			WriteTimeout(30*time.Second).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("zero duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for zero write timeout")
			}
		}()
		we.New().WriteTimeout(0)
	})

	t.Run("negative duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for negative write timeout")
			}
		}()
		we.New().WriteTimeout(-5 * time.Second)
	})
}

func TestBuilderIdleTimeout(t *testing.T) {
	t.Run("valid duration", func(t *testing.T) {
		engine := we.New().
			IdleTimeout(60*time.Second).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("zero duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for zero idle timeout")
			}
		}()
		we.New().IdleTimeout(0)
	})

	t.Run("negative duration panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for negative idle timeout")
			}
		}()
		we.New().IdleTimeout(-1 * time.Second)
	})
}

func TestBuilderMaxHeaderBytes(t *testing.T) {
	t.Run("valid value", func(t *testing.T) {
		engine := we.New().
			MaxHeaderBytes(1<<20).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("zero value panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for zero max header bytes")
			}
		}()
		we.New().MaxHeaderBytes(0)
	})

	t.Run("negative value panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for negative max header bytes")
			}
		}()
		we.New().MaxHeaderBytes(-1)
	})
}

// --- Engine Builder ErrorHandler Test ---

type testErrorHandler struct {
	called bool
}

func (h *testErrorHandler) HandleError(w http.ResponseWriter, err error, rs we.RequestScope) {
	h.called = true
	w.WriteHeader(http.StatusInternalServerError)
}

func TestBuilderErrorHandler(t *testing.T) {
	t.Run("custom error handler is set", func(t *testing.T) {
		handler := &testErrorHandler{}
		engine := we.New().
			ErrorHandler(handler).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return fmt.Errorf("test error")
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("nil error handler does not panic", func(t *testing.T) {
		// Setting nil error handler should be ok; Build() will provide a default
		engine := we.New().
			ErrorHandler(nil).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})
}

// --- Engine Builder Logger Test ---

type testLogger struct {
	messages []string
}

func (l *testLogger) Debug(msg string) { l.messages = append(l.messages, "[DEBUG] "+msg) }
func (l *testLogger) Info(msg string)  { l.messages = append(l.messages, "[INFO] "+msg) }
func (l *testLogger) Warn(msg string)  { l.messages = append(l.messages, "[WARN] "+msg) }
func (l *testLogger) Error(msg string) { l.messages = append(l.messages, "[ERROR] "+msg) }
func (l *testLogger) Log(level int, msg string) {
	l.messages = append(l.messages, fmt.Sprintf("[%d] %s", level, msg))
}

func TestBuilderLogger(t *testing.T) {
	t.Run("custom logger is set", func(t *testing.T) {
		logger := &testLogger{}
		engine := we.New().
			Logger(logger).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil")
		}
	})

	t.Run("nil logger panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for nil logger")
			}
		}()
		we.New().Logger(nil)
	})
}

// --- Builder chaining test ---

func TestBuilderChaining(t *testing.T) {
	t.Run("all builder methods chain correctly", func(t *testing.T) {
		logger := &testLogger{}
		handler := &testErrorHandler{}

		engine := we.New().
			ReadHeaderTimeout(5*time.Second).
			ReadTimeout(10*time.Second).
			WriteTimeout(30*time.Second).
			IdleTimeout(120*time.Second).
			MaxHeaderBytes(1<<20).
			Logger(logger).
			ErrorHandler(handler).
			Handle("/test", func(w http.ResponseWriter, rs we.RequestScope) error {
				return nil
			}).
			Build()
		if engine == nil {
			t.Fatal("expected engine to be non-nil after chaining all builder methods")
		}
	})
}

// --- Session Delete and Clear Tests ---

func TestSessionDelete(t *testing.T) {
	t.Run("delete existing key", func(t *testing.T) {
		scope := test.MockedRequestScope("GET", "http://localhost/test")
		session := scope.Session()

		session.Set("key1", "value1")
		session.Set("key2", "value2")

		if session.Get("key1") != "value1" {
			t.Fatal("expected key1 to be set")
		}

		session.Delete("key1")

		if session.Get("key1") != nil {
			t.Fatal("expected key1 to be nil after delete")
		}
		// key2 should still exist
		if session.Get("key2") != "value2" {
			t.Fatal("expected key2 to still be set")
		}
	})

	t.Run("delete non-existing key does not panic", func(t *testing.T) {
		scope := test.MockedRequestScope("GET", "http://localhost/test")
		session := scope.Session()

		// Should not panic
		session.Delete("nonexistent")

		if session.Get("nonexistent") != nil {
			t.Fatal("expected nonexistent key to be nil")
		}
	})
}

func TestSessionClear(t *testing.T) {
	t.Run("clear removes all attributes", func(t *testing.T) {
		scope := test.MockedRequestScope("GET", "http://localhost/test")
		session := scope.Session()

		session.Set("key1", "value1")
		session.Set("key2", "value2")
		session.Set("key3", "value3")

		if session.Get("key1") != "value1" {
			t.Fatal("expected key1 to be set before clear")
		}

		session.Clear()

		if session.Get("key1") != nil {
			t.Fatal("expected key1 to be nil after clear")
		}
		if session.Get("key2") != nil {
			t.Fatal("expected key2 to be nil after clear")
		}
		if session.Get("key3") != nil {
			t.Fatal("expected key3 to be nil after clear")
		}
	})

	t.Run("clear on empty session does not panic", func(t *testing.T) {
		scope := test.MockedRequestScope("GET", "http://localhost/test")
		session := scope.Session()

		// Should not panic
		session.Clear()
	})

	t.Run("set after clear works", func(t *testing.T) {
		scope := test.MockedRequestScope("GET", "http://localhost/test")
		session := scope.Session()

		session.Set("key1", "value1")
		session.Clear()
		session.Set("key2", "value2")

		if session.Get("key1") != nil {
			t.Fatal("expected key1 to be nil after clear")
		}
		if session.Get("key2") != "value2" {
			t.Fatal("expected key2 to be set after clear")
		}
	})
}

// --- SessionManager Logger builder method test ---

func TestSessionManagerLogger(t *testing.T) {
	t.Run("custom logger is set", func(t *testing.T) {
		logger := &testLogger{}
		sm := we.DefaultSessionManager().
			Logger(logger).
			Build()
		if sm == nil {
			t.Fatal("expected session manager to be non-nil")
		}
	})

	t.Run("nil logger panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for nil logger")
			}
		}()
		we.DefaultSessionManager().Logger(nil)
	})
}

// --- DefaultLogger Debug, Warn, Log tests ---

func TestDefaultLoggerDebug(t *testing.T) {
	logger := we.NewDefaultLogger()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger.Debug("test debug message")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "[DEBUG]") {
		t.Fatalf("expected output to contain [DEBUG], got: %s", output)
	}
	if !strings.Contains(output, "test debug message") {
		t.Fatalf("expected output to contain 'test debug message', got: %s", output)
	}
}

func TestDefaultLoggerWarn(t *testing.T) {
	logger := we.NewDefaultLogger()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger.Warn("test warn message")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "[WARN]") {
		t.Fatalf("expected output to contain [WARN], got: %s", output)
	}
	if !strings.Contains(output, "test warn message") {
		t.Fatalf("expected output to contain 'test warn message', got: %s", output)
	}
}

func TestDefaultLoggerLog(t *testing.T) {
	logger := we.NewDefaultLogger()

	t.Run("log with debug level", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		logger.Log(we.LogLevelDebug, "debug via log")

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "[DEBUG]") {
			t.Fatalf("expected output to contain [DEBUG], got: %s", output)
		}
		if !strings.Contains(output, "debug via log") {
			t.Fatalf("expected output to contain 'debug via log', got: %s", output)
		}
	})

	t.Run("log with info level", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		logger.Log(we.LogLevelInfo, "info via log")

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "[INFO]") {
			t.Fatalf("expected output to contain [INFO], got: %s", output)
		}
	})

	t.Run("log with warn level", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		logger.Log(we.LogLevelWarn, "warn via log")

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "[WARN]") {
			t.Fatalf("expected output to contain [WARN], got: %s", output)
		}
	})

	t.Run("log with error level", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		logger.Log(we.LogLevelError, "error via log")

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "[ERROR]") {
			t.Fatalf("expected output to contain [ERROR], got: %s", output)
		}
	})

	t.Run("log with unknown level", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		logger.Log(99, "unknown via log")

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		if !strings.Contains(output, "[UNKNOWN]") {
			t.Fatalf("expected output to contain [UNKNOWN], got: %s", output)
		}
		if !strings.Contains(output, "unknown via log") {
			t.Fatalf("expected output to contain 'unknown via log', got: %s", output)
		}
	})
}

// --- Tests for updateEndpoint via filter flow events ---

func TestBuilderUpdateEndpointViaContinue(t *testing.T) {
	t.Run("filter returns Continue with new path", func(t *testing.T) {
		var handledPath string
		engine := we.New().
			Filter(we.FilterFunction(func(headers http.Header, scope we.RequestScope) error {
				// Return Continue with a new endpoint - this triggers updateEndpoint and skips remaining filters
				return events.Continue.WithAttribute("/new-path?key=value")
			})).
			Handle("/original-path", func(w http.ResponseWriter, rs we.RequestScope) error {
				// After updateEndpoint, the request URL path should be updated
				handledPath = rs.Request().URL.Path
				w.Write([]byte("reached handler"))
				return nil
			}).
			Build()

		req := httptest.NewRequest("GET", "/original-path", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		// updateEndpoint should have changed the URL path on the scope's request
		if handledPath != "/new-path" {
			t.Fatalf("expected handler path to be /new-path, got: %s", handledPath)
		}
	})

	t.Run("filter returns Continue with query parameters", func(t *testing.T) {
		var queryValue string
		engine := we.New().
			Filter(we.FilterFunction(func(headers http.Header, scope we.RequestScope) error {
				return events.Continue.WithAttribute("/target?param=hello")
			})).
			Handle("/start", func(w http.ResponseWriter, rs we.RequestScope) error {
				queryValue = rs.Request().URL.RawQuery
				w.Write([]byte("ok"))
				return nil
			}).
			Build()

		req := httptest.NewRequest("GET", "/start", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		if queryValue != "param=hello" {
			t.Fatalf("expected query to be 'param=hello', got: %s", queryValue)
		}
	})
}

func TestBuilderUpdateEndpointViaUpdate(t *testing.T) {
	t.Run("filter returns Update with new path continues filter chain", func(t *testing.T) {
		filterOrder := []string{}
		engine := we.New().
			Filter(we.FilterFunction(func(headers http.Header, scope we.RequestScope) error {
				filterOrder = append(filterOrder, "filter1")
				// Return Update - updates the endpoint but continues with remaining filters
				return events.Update.WithAttribute("/updated-path?q=1")
			})).
			Filter(we.FilterFunction(func(headers http.Header, scope we.RequestScope) error {
				filterOrder = append(filterOrder, "filter2")
				return nil
			})).
			Handle("/original", func(w http.ResponseWriter, rs we.RequestScope) error {
				w.Write([]byte("updated"))
				return nil
			}).
			Build()

		req := httptest.NewRequest("GET", "/original", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		// Both filters should have been called (Update continues the chain)
		if len(filterOrder) != 2 {
			t.Fatalf("expected 2 filters to be called, got: %d", len(filterOrder))
		}
		if filterOrder[0] != "filter1" || filterOrder[1] != "filter2" {
			t.Fatalf("expected filter order [filter1, filter2], got: %v", filterOrder)
		}
	})

	t.Run("update endpoint without query string", func(t *testing.T) {
		var handledPath string
		engine := we.New().
			Filter(we.FilterFunction(func(headers http.Header, scope we.RequestScope) error {
				return events.Update.WithAttribute("/no-query")
			})).
			Handle("/old-path", func(w http.ResponseWriter, rs we.RequestScope) error {
				handledPath = rs.Request().URL.Path
				w.Write([]byte("no query"))
				return nil
			}).
			Build()

		req := httptest.NewRequest("GET", "/old-path?old=param", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		if handledPath != "/no-query" {
			t.Fatalf("expected handler path to be /no-query, got: %s", handledPath)
		}
	})
}
