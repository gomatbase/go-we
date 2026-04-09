// Copyright 2025-2026 GOM. All rights reserved.
// Since 14/01/2025 By GOM
// Licensed under MIT License

package we_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/test"
)

func waitForServer(port int) {
	for {
		if Conn, e := net.Dial("tcp", fmt.Sprintf("localhost:%d", port)); e == nil {
			_ = Conn.Close()
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
}

type waitingChannel chan bool

func (w waitingChannel) Wait(timeout time.Duration) bool {
	select {
	case result := <-w:
		return result
	case <-time.After(timeout):
		return false
	}
}

func (w waitingChannel) Signal() {
	w <- true
}

var startingPort = int32(60000)

func nextPort() (int, string) {
	p := atomic.AddInt32(&startingPort, 1)
	return int(p), fmt.Sprintf(":%d", p)
}

func newWaitingChannel() waitingChannel {
	return make(chan bool, 1)
}

func start(engine we.Engine) string {
	port, portStr := nextPort()
	go engine.Listen(portStr)
	waitForServer(port)
	return portStr
}

func simpleHandler(response string) func(writer http.ResponseWriter, request we.RequestScope) error {
	return func(writer http.ResponseWriter, request we.RequestScope) error {
		_, _ = writer.Write([]byte(response))
		return nil
	}
}

func TestWebEngineShutdown(t *testing.T) {
	t.Run("Test Shutdown on engine with unmanaged listener", func(t *testing.T) {
		engine := we.New().Build()

		if engine.Shutdown() == nil {
			t.Error("Expected error on shutdown with unmanaged listener")
		}
	})
	t.Run("Test Gracious Shutdown on engine with unmanaged listener", func(t *testing.T) {
		engine := we.New().Build()

		if engine.GraciouslyShutdown(time.Minute) == nil {
			t.Error("Expected error on shutdown with unmanaged listener")
		}
	})
	t.Run("Test Shutdown on engine", func(t *testing.T) {
		builder := we.New()
		handlerThreadControl := newWaitingChannel()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			handlerThreadControl.Wait(time.Second * 10)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		var serverError error
		serverThreadControl := newWaitingChannel()
		port, portStr := nextPort()
		engine := builder.Build()
		go func() {
			serverError = engine.Listen(portStr)
			serverThreadControl.Signal()
		}()
		waitForServer(port)

		var result []byte
		var clientError error
		clientThreadControl := newWaitingChannel()
		go func() {
			clientThreadControl.Signal()
			result, clientError = test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
			clientThreadControl.Signal()
		}()

		// let's just give some time for the client to initiate the request
		clientThreadControl.Wait(time.Minute)
		time.Sleep(time.Millisecond * 100)

		if e := engine.Shutdown(); e != nil {
			t.Error("Expected shutdown to return no errors", e)
		}

		// and wait for the threads to finish
		clientThreadControl.Wait(time.Minute)
		serverThreadControl.Wait(time.Minute)

		var urlError *url.Error
		if string(result) == "success" {
			t.Error("Unexpected response from server")
		} else if clientError == nil {
			t.Error("Expected client error")
		} else if !errors.As(clientError, &urlError) {
			t.Error("Expected client error to be url.Error")
		} else if urlError.Unwrap() != io.EOF {
			t.Error("Expected client error to be EOF")
		}
		if !errors.Is(serverError, http.ErrServerClosed) {
			t.Error("Expected server closed return error")
		}
	})
	t.Run("Test Timed-out Gracious Shutdown on builder", func(t *testing.T) {
		builder := we.New()
		handlerThreadControl := newWaitingChannel()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			handlerThreadControl.Wait(time.Minute)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		var serverError error
		serverThreadControl := newWaitingChannel()
		port, portStr := nextPort()
		engine := builder.Build()
		go func() {
			serverError = engine.Listen(portStr)
			serverThreadControl.Signal()
		}()
		waitForServer(port)

		var result []byte
		var clientError error
		clientThreadControl := newWaitingChannel()
		go func() {
			clientThreadControl.Signal()
			result, clientError = test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
			clientThreadControl.Signal()
		}()

		// let's just give some time for the client to initiate the request
		clientThreadControl.Wait(time.Minute)
		time.Sleep(time.Millisecond * 100)

		if !errors.Is(engine.GraciouslyShutdown(time.Second), context.DeadlineExceeded) {
			t.Error("Expected shutdown to return a timeout error")
		}

		// and wait for the threads to finish
		clientThreadControl.Wait(time.Minute)
		serverThreadControl.Wait(time.Minute)

		var urlError *url.Error
		if string(result) == "success" {
			t.Error("Unexpected response from server")
		} else if clientError == nil {
			t.Error("Expected client error")
		} else if !errors.As(clientError, &urlError) {
			t.Error("Expected client error to be url.Error")
		} else if urlError.Unwrap() != io.EOF {
			t.Error("Expected client error to be EOF")
		}
		if !errors.Is(serverError, http.ErrServerClosed) {
			t.Error("Expected server closed return error")
		}
	})
	t.Run("Test Gracious Shutdown on builder", func(t *testing.T) {
		builder := we.New()
		handlerThreadControl := newWaitingChannel()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			handlerThreadControl.Wait(time.Minute)
			time.Sleep(time.Second)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		var serverError error
		serverThreadControl := newWaitingChannel()
		port, portStr := nextPort()
		engine := builder.Build()
		go func() {
			serverError = engine.Listen(portStr)
			serverThreadControl.Signal()
		}()
		waitForServer(port)

		var result []byte
		var clientError error
		clientThreadControl := newWaitingChannel()
		go func() {
			clientThreadControl.Signal()
			result, clientError = test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
			clientThreadControl.Signal()
		}()

		// let's just give some time for the client to initiate the request
		clientThreadControl.Wait(time.Minute)
		time.Sleep(time.Millisecond * 100)

		handlerThreadControl.Signal()
		if e := engine.GraciouslyShutdown(time.Minute); e != nil {
			t.Error("Expected shutdown to return without errors:", e)
		}

		// and wait for the threads to finish
		clientThreadControl.Wait(time.Minute)
		serverThreadControl.Wait(time.Minute)

		if string(result) != "success" {
			t.Error("Expected server to still finish response")
		} else if e := clientError; e != nil {
			t.Error("Expected no client error:", e)
		}
		if !errors.Is(serverError, http.ErrServerClosed) {
			t.Error("Expected server closed return error")
		}
	})
}

func TestWebbuilderSimpleUse(t *testing.T) {
	t.Run("Test successful simple request handling", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", simpleHandler("success"))
		engine := builder.Build()
		portStr := start(engine)

		result, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
		if string(result) != "success" {
			t.Error("Unexpected response from server")
		} else if e != nil {
			t.Error("Expected no client error:", e)
		}

		_ = engine.Shutdown()
	})
}

func TestWebbuilderPathHandling(t *testing.T) {
	t.Run("Test plain path handling", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", simpleHandler("success"))
		builder.Handle("/somewhere", simpleHandler("success2"))

		engine := builder.Build()
		portStr := start(engine)

		bytes, e := test.Request(fmt.Sprintf("http://localhost%s/somewhere", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success2" {
			t.Error("Expected success handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/somewhere/else", portStr)).Get()
		if e == nil {
			t.Error("Expected 404 error")
		} else if e.Error() != "failed request: 404 Not Found" {
			t.Error("Expected a 404 response for unhandled path:", e)
		}

		_ = engine.Shutdown()
	})
	t.Run("Test path with variables handling", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/{var}", simpleHandler("success"))
		builder.Handle("/{var}/somewhere", simpleHandler("success2"))

		engine := builder.Build()
		portStr := start(engine)

		bytes, e := test.Request(fmt.Sprintf("http://localhost%s/somewhere", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/something", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/something/somewhere", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success2" {
			t.Error("Expected second success handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/something/else", portStr)).Get()
		if e == nil {
			t.Error("Expected 404 error")
		} else if e.Error() != "failed request: 404 Not Found" {
			t.Error("Expected a 404 response for unhandled path:", e)
		}

		_ = engine.Shutdown()
	})
	t.Run("Test wildcard handling", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/*", simpleHandler("success"))

		engine := builder.Build()
		portStr := start(engine)

		bytes, e := test.Request(fmt.Sprintf("http://localhost%s/somewhere", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response", string(bytes))
		}

		// single wildcard now matches root path
		bytes, e = test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response for root path", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/somewhere/else", portStr)).Get()
		if e == nil {
			t.Error("Expected 404 error")
		} else if e.Error() != "failed request: 404 Not Found" {
			t.Error("Expected a 404 response for unhandled path:", e)
		}

		_ = engine.Shutdown()
	})
	t.Run("Test double wildcard handling", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/**", simpleHandler("success"))

		engine := builder.Build()
		portStr := start(engine)

		bytes, e := test.Request(fmt.Sprintf("http://localhost%s/somewhere", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/somewhere/else", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response for multi-segment path", string(bytes))
		}

		// double wildcard now matches root path
		bytes, e = test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected success handler response for root path", string(bytes))
		}

		_ = engine.Shutdown()
	})
	t.Run("Test path handling precedence", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/somewhere/specific", simpleHandler("fixed path"))
		builder.Handle("/{var}/specific", simpleHandler("variable"))
		builder.Handle("/*/*", simpleHandler("wildcard"))
		builder.Handle("/**", simpleHandler("double wildcard"))

		engine := builder.Build()
		portStr := start(engine)

		bytes, e := test.Request(fmt.Sprintf("http://localhost%s/somewhere/specific", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "fixed path" {
			t.Error("Expected fixed path handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/something/specific", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "variable" {
			t.Error("Expected variable handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/something/random", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "wildcard" {
			t.Error("Expected wildcard handler response", string(bytes))
		}

		bytes, e = test.Request(fmt.Sprintf("http://localhost%s/something/random/more", portStr)).Get()
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if string(bytes) != "double wildcard" {
			t.Error("Expected double wildcard handler response", string(bytes))
		}

		_ = engine.Shutdown()
	})
}

func TestRequestScopeMethods(t *testing.T) {
	t.Run("Test path variables", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/user/{id}/profile/{section}", func(w http.ResponseWriter, r we.RequestScope) error {
			id := r.Var("id")
			section := r.Var("section")
			missing := r.Var("missing")

			idVal, idFound := r.LookupVar("id")
			_, missingFound := r.LookupVar("missing")

			if id != "123" || section != "settings" {
				return fmt.Errorf("unexpected path variables: id=%s, section=%s", id, section)
			}
			if missing != "" {
				return fmt.Errorf("expected empty string for missing variable")
			}
			if !idFound || idVal != "123" {
				return fmt.Errorf("LookupVar failed for id")
			}
			if missingFound {
				return fmt.Errorf("expected false for missing variable")
			}

			_, _ = w.Write([]byte("success"))
			return nil
		})

		engine := builder.Build()
		portStr := start(engine)
		result, e := test.Request(fmt.Sprintf("http://localhost%s/user/123/profile/settings", portStr)).Get()

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if string(result) != "success" {
			t.Error("Handler error:", string(result))
		}

		_ = engine.Shutdown()
	})

	t.Run("Test query parameters", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/search", func(w http.ResponseWriter, r we.RequestScope) error {
			q := r.Parameter("q")
			missing := r.Parameter("missing")

			tags := r.Parameters("tag")
			emptyTags := r.Parameters("notag")

			qVal, qFound := r.LookupParameter("q")
			_, missingFound := r.LookupParameter("missing")

			tagVals, tagsFound := r.LookupParameters("tag")
			_, notagsFound := r.LookupParameters("notag")

			if q != "golang" {
				return fmt.Errorf("unexpected query param: q=%s", q)
			}
			if missing != "" {
				return fmt.Errorf("expected empty string for missing param")
			}
			if len(tags) != 2 || tags[0] != "web" || tags[1] != "framework" {
				return fmt.Errorf("unexpected tags: %v", tags)
			}
			if len(emptyTags) != 0 {
				return fmt.Errorf("expected empty slice for missing tags")
			}
			if !qFound || qVal != "golang" {
				return fmt.Errorf("LookupParameter failed for q")
			}
			if missingFound {
				return fmt.Errorf("expected false for missing parameter")
			}
			if !tagsFound || len(tagVals) != 2 {
				return fmt.Errorf("LookupParameters failed for tag")
			}
			if notagsFound {
				return fmt.Errorf("expected false for missing parameters")
			}

			_, _ = w.Write([]byte("success"))
			return nil
		})

		engine := builder.Build()
		portStr := start(engine)
		result, e := test.Request(fmt.Sprintf("http://localhost%s/search?q=golang&tag=web&tag=framework", portStr)).Get()

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if string(result) != "success" {
			t.Error("Handler error:", string(result))
		}

		_ = engine.Shutdown()
	})

	t.Run("Test request scope attributes", func(t *testing.T) {
		builder := we.New()
		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			r.Set("userId", "user123")
			r.Set("role", "admin")
			return nil
		}))
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			userId := r.Get("userId")
			role := r.Get("role")
			missing := r.Get("missing")

			if userId != "user123" || role != "admin" {
				return fmt.Errorf("unexpected attributes: userId=%v, role=%v", userId, role)
			}
			if missing != nil {
				return fmt.Errorf("expected nil for missing attribute")
			}

			_, _ = w.Write([]byte("success"))
			return nil
		})

		engine := builder.Build()
		portStr := start(engine)
		result, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if string(result) != "success" {
			t.Error("Handler error:", string(result))
		}

		_ = engine.Shutdown()
	})

	t.Run("Test session attributes", func(t *testing.T) {
		builder := we.New()
		sessionManager := we.DefaultSessionManager().
			CookieSecure(false).
			Build()
		builder.SessionManager(sessionManager)

		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			if !r.HasSession() {
				return fmt.Errorf("expected session to be present")
			}

			// Test setting and getting in same request
			r.SetInSession("counter", 42)
			r.SetInSession("user", "alice")

			counter := r.GetFromSession("counter")
			user := r.GetFromSession("user")
			missing := r.GetFromSession("missing")

			if counter != 42 || user != "alice" {
				return fmt.Errorf("unexpected session attributes: counter=%v, user=%v", counter, user)
			}
			if missing != nil {
				return fmt.Errorf("expected nil for missing session attribute")
			}

			_, _ = w.Write([]byte("success"))
			return nil
		})

		engine := builder.Build()
		portStr := start(engine)
		result, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if string(result) != "success" {
			t.Error("Handler error:", string(result))
		}

		_ = engine.Shutdown()
	})

	t.Run("Test Request and Context methods", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			req := r.Request()
			ctx := r.Context()

			if req == nil {
				return fmt.Errorf("expected Request() to return non-nil")
			}
			if ctx == nil {
				return fmt.Errorf("expected Context() to return non-nil")
			}
			if req.Context() != ctx {
				return fmt.Errorf("expected Context() to match Request().Context()")
			}

			_, _ = w.Write([]byte("success"))
			return nil
		})

		engine := builder.Build()
		portStr := start(engine)
		result, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).Get()

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if string(result) != "success" {
			t.Error("Handler error:", string(result))
		}

		_ = engine.Shutdown()
	})
}

func TestWebbuilderMethodHandling(t *testing.T) {
	t.Run("Test HandleMethod routing", func(t *testing.T) {
		builder := we.New()
		builder.HandleMethod(http.MethodGet, "/resource", simpleHandler("GET response"))
		builder.HandleMethod(http.MethodPost, "/resource", simpleHandler("POST response"))
		builder.HandleMethod(http.MethodPut, "/resource", simpleHandler("PUT response"))
		builder.HandleMethod(http.MethodDelete, "/resource", simpleHandler("DELETE response"))

		engine := builder.Build()
		portStr := start(engine)

		result, e := test.Request(fmt.Sprintf("http://localhost%s/resource", portStr)).Get()
		if e != nil {
			t.Error("GET error:", e)
		} else if string(result) != "GET response" {
			t.Error("Unexpected GET response:", string(result))
		}

		req := test.Request(fmt.Sprintf("http://localhost%s/resource", portStr))
		req.WithContent([]byte("data"))
		resp, e := req.DoWithResponse(http.MethodPost)
		if e != nil {
			t.Error("POST error:", e)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "POST response" {
			t.Error("Unexpected POST response:", string(body))
		}

		_ = engine.Shutdown()
	})
}

func TestWebbuilderFilterHandling(t *testing.T) {
	t.Run("Test filter can set headers", func(t *testing.T) {
		builder := we.New()

		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			h.Set("X-Custom-Header", "test-value")
			h.Set("X-Request-Id", "12345")
			return nil
		}))

		builder.Handle("/", simpleHandler("success"))

		engine := builder.Build()
		portStr := start(engine)
		resp, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if resp.Header.Get("X-Custom-Header") != "test-value" {
			t.Error("Expected X-Custom-Header to be set")
		} else if resp.Header.Get("X-Request-Id") != "12345" {
			t.Error("Expected X-Request-Id to be set")
		}

		_ = engine.Shutdown()
	})

	t.Run("Test filter error stops request", func(t *testing.T) {
		builder := we.New()

		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			return events.UnauthorizedError
		}))

		builder.Handle("/", simpleHandler("should not reach here"))

		engine := builder.Build()
		portStr := start(engine)
		resp, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if resp.StatusCode != http.StatusUnauthorized {
			t.Error("Expected 401 status code, got:", resp.StatusCode)
		}

		_ = engine.Shutdown()
	})

	t.Run("Test multiple filters execute in order", func(t *testing.T) {
		builder := we.New()

		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			h.Set("X-Filter-1", "executed")
			r.Set("filter1", true)
			return nil
		}))

		builder.Filter(we.FilterFunction(func(h http.Header, r we.RequestScope) error {
			if r.Get("filter1") != true {
				return fmt.Errorf("filter1 should have executed first")
			}
			h.Set("X-Filter-2", "executed")
			return nil
		}))

		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			if r.Get("filter1") != true {
				return fmt.Errorf("filter1 did not execute")
			}
			_, _ = w.Write([]byte("success"))
			return nil
		})

		engine := builder.Build()
		portStr := start(engine)
		resp, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)

		if e != nil {
			t.Error("Unexpected error:", e)
		} else if resp.Header.Get("X-Filter-1") != "executed" {
			t.Error("Expected X-Filter-1 to be set")
		} else if resp.Header.Get("X-Filter-2") != "executed" {
			t.Error("Expected X-Filter-2 to be set")
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "success" {
			t.Error("Handler did not execute properly")
		}

		_ = engine.Shutdown()
	})
}

func TestWebbuilderDefaultErrorHandling(t *testing.T) {
	t.Run("Test simple application error", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return fmt.Errorf("applicational error")
		})

		port, portStr := nextPort()
		engine := builder.Build()
		go engine.Listen(portStr)
		waitForServer(port)

		response, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if response.StatusCode != http.StatusInternalServerError {
			t.Error("Expected internal server error for unhandled error:", response.StatusCode)
		} else if bytes, e := io.ReadAll(response.Body); e != nil {
			t.Error("Unexpected error reading response body:", e)
		} else if len(bytes) != 0 {
			t.Error("Expected empty response body for unhandled error", string(bytes))
		}

		_ = engine.Shutdown()
	})
	t.Run("Test uncaught panic", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			panic("system error")
		})

		port, portStr := nextPort()
		engine := builder.Build()
		go engine.Listen(portStr)
		waitForServer(port)

		response, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if response.StatusCode != http.StatusInternalServerError {
			t.Error("Expected internal server error for unhandled error:", response.StatusCode)
		} else if bytes, e := io.ReadAll(response.Body); e != nil {
			t.Error("Unexpected error reading response body:", e)
		} else if len(bytes) != 0 {
			t.Error("Expected empty response body for unhandled error", string(bytes))
		}

		_ = engine.Shutdown()
	})
	t.Run("Test we event error handling", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return events.New(http.StatusTeapot, "we event error")
		})

		port, portStr := nextPort()
		engine := builder.Build()
		go engine.Listen(portStr)
		waitForServer(port)

		response, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if response.StatusCode != http.StatusTeapot {
			t.Error("Expected teapot (418) status code:", response.StatusCode)
		} else if bytes, e := io.ReadAll(response.Body); e != nil {
			t.Error("Unexpected error reading response body:", e)
		} else if len(bytes) != 0 {
			t.Error("Expected empty response body for unhandled error", string(bytes))
		} else if response.Header.Values("Content-Type") != nil {
			t.Error("Expected content-type to not be present")
		}

		_ = engine.Shutdown()
	})
	t.Run("Test we event error handling with payload", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			return events.NewPayload(http.StatusTeapot, "we event error", &events.Payload{ContentTypeHint: "text/plain", Content: []byte("something happened")})
		})

		port, portStr := nextPort()
		engine := builder.Build()
		go engine.Listen(portStr)
		waitForServer(port)

		response, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if response.StatusCode != http.StatusTeapot {
			t.Error("Expected teapot (418) status code:", response.StatusCode)
		} else if bytes, e := io.ReadAll(response.Body); e != nil {
			t.Error("Unexpected error reading response body:", e)
		} else if string(bytes) != "something happened" {
			t.Error("Expected error message to be \"something happened\"", string(bytes))
		} else if response.Header.Get("Content-Type") != "text/plain" {
			t.Error("expected error message to be marshalled as text/plain")
		}

		_ = engine.Shutdown()
	})
	t.Run("Test application error after starting to write response", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			_, _ = w.Write([]byte("success"))
			return fmt.Errorf("applicational error")
		})

		port, portStr := nextPort()
		engine := builder.Build()
		go engine.Listen(portStr)
		waitForServer(port)

		response, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if response.StatusCode != http.StatusOK {
			t.Error("Expected error occurring after response started to be written to get the standard expected successful code:", response.StatusCode)
		} else if bytes, e := io.ReadAll(response.Body); e != nil {
			t.Error("Unexpected error reading response body:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected error occurring after response success already being sent", string(bytes))
		}

		_ = engine.Shutdown()
	})
	t.Run("Test panic after starting to write response", func(t *testing.T) {
		builder := we.New()
		builder.Handle("/", func(w http.ResponseWriter, r we.RequestScope) error {
			_, _ = w.Write([]byte("success"))
			panic("applicational error")
		})

		port, portStr := nextPort()
		engine := builder.Build()
		go engine.Listen(portStr)
		waitForServer(port)

		response, e := test.Request(fmt.Sprintf("http://localhost%s", portStr)).DoWithResponse(http.MethodGet)
		if e != nil {
			t.Error("Unexpected call error:", e)
		} else if response.StatusCode != http.StatusOK {
			t.Error("Expected error occurring after response started to be written to get the standard expected successful code:", response.StatusCode)
		} else if bytes, e := io.ReadAll(response.Body); e != nil {
			t.Error("Unexpected error reading response body:", e)
		} else if string(bytes) != "success" {
			t.Error("Expected panic occurring after response already being sent ", string(bytes))
		}

		_ = engine.Shutdown()
	})
}
