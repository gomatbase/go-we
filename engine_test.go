// Copyright 2025 GOM. All rights reserved.
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
	"testing"
	"time"

	"github.com/gomatbase/go-we"
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

func newWaitingChannel() waitingChannel {
	return make(chan bool, 1)
}

func TestWebEngineShutdown(t *testing.T) {
	t.Run("Test Shutdown on engine with unmanaged listener", func(t *testing.T) {
		var shutdown func() error
		engine := we.New()
		engine.HookShutdownFunction(&shutdown)

		if shutdown() == nil {
			t.Error("Expected error on shutdown with unmanaged listener")
		}
	})
	t.Run("Test Gracious Shutdown on engine with unmanaged listener", func(t *testing.T) {
		var shutdown func(timeout time.Duration) error
		engine := we.New()
		engine.HookGraciousShutdownFunction(&shutdown)

		if shutdown(time.Minute) == nil {
			t.Error("Expected error on shutdown with unmanaged listener")
		}
	})
	t.Run("Test Shutdown on engine", func(t *testing.T) {
		var shutdown func() error
		engine := we.New()
		engine.HookShutdownFunction(&shutdown)
		handlerThreadControl := newWaitingChannel()
		engine.Handle("/", func(w we.ResponseWriter, r we.RequestScope) error {
			handlerThreadControl.Wait(time.Second * 10)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		var serverError error
		serverThreadControl := newWaitingChannel()
		go func() {
			serverError = engine.Listen(":58730")
			serverThreadControl.Signal()
		}()
		waitForServer(58730)

		var result []byte
		var clientError error
		clientThreadControl := newWaitingChannel()
		go func() {
			clientThreadControl.Signal()
			result, clientError = test.Request("http://localhost:58730").Get()
			clientThreadControl.Signal()
		}()

		// let's just give some time for the client to initiate the request
		clientThreadControl.Wait(time.Minute)
		time.Sleep(time.Millisecond * 100)

		if e := shutdown(); e != nil {
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
	t.Run("Test Timed-out Gracious Shutdown on engine", func(t *testing.T) {
		var shutdown func(timeout time.Duration) error
		engine := we.New()
		engine.HookGraciousShutdownFunction(&shutdown)
		handlerThreadControl := newWaitingChannel()
		engine.Handle("/", func(w we.ResponseWriter, r we.RequestScope) error {
			handlerThreadControl.Wait(time.Minute)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		var serverError error
		serverThreadControl := newWaitingChannel()
		go func() {
			serverError = engine.Listen(":58730")
			serverThreadControl.Signal()
		}()
		waitForServer(58730)

		var result []byte
		var clientError error
		clientThreadControl := newWaitingChannel()
		go func() {
			clientThreadControl.Signal()
			result, clientError = test.Request("http://localhost:58730").Get()
			clientThreadControl.Signal()
		}()

		// let's just give some time for the client to initiate the request
		clientThreadControl.Wait(time.Minute)
		time.Sleep(time.Millisecond * 100)

		if !errors.Is(shutdown(time.Second), context.DeadlineExceeded) {
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
	t.Run("Test Gracious Shutdown on engine", func(t *testing.T) {
		var shutdown func(timeout time.Duration) error
		engine := we.New()
		engine.HookGraciousShutdownFunction(&shutdown)
		handlerThreadControl := newWaitingChannel()
		engine.Handle("/", func(w we.ResponseWriter, r we.RequestScope) error {
			handlerThreadControl.Wait(time.Minute)
			time.Sleep(time.Second)
			_, _ = w.Write([]byte("success"))
			return nil
		})

		var serverError error
		serverThreadControl := newWaitingChannel()
		go func() {
			serverError = engine.Listen(":58730")
			serverThreadControl.Signal()
		}()
		waitForServer(58730)

		var result []byte
		var clientError error
		clientThreadControl := newWaitingChannel()
		go func() {
			clientThreadControl.Signal()
			result, clientError = test.Request("http://localhost:58730").Get()
			clientThreadControl.Signal()
		}()

		// let's just give some time for the client to initiate the request
		clientThreadControl.Wait(time.Minute)
		time.Sleep(time.Millisecond * 100)

		handlerThreadControl.Signal()
		if e := shutdown(time.Minute); e != nil {
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
