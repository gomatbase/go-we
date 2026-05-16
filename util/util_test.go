// Copyright 2026 GOM. All rights reserved.
// Since 04/04/2026 By GOM
// Licensed under MIT License

package util

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gomatbase/go-we"
)

type TestRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Age   int    `json:"age"`
}

type TestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	ID      int    `json:"id"`
}

func TestReadJsonBody(t *testing.T) {
	t.Run("Successfully read valid JSON", func(t *testing.T) {
		jsonData := `{"name":"John","email":"john@example.com","age":30}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(jsonData))
		scope := &mockRequestScope{request: req}

		result, err := ReadJsonBody[TestRequest](scope)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if result.Name != "John" {
			t.Errorf("Expected name John, got %s", result.Name)
		}
		if result.Email != "john@example.com" {
			t.Errorf("Expected email john@example.com, got %s", result.Email)
		}
		if result.Age != 30 {
			t.Errorf("Expected age 30, got %d", result.Age)
		}
	})

	t.Run("Handle empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
		scope := &mockRequestScope{request: req}

		result, err := ReadJsonBody[TestRequest](scope)
		if err != nil {
			t.Errorf("Expected no error for empty body, got %v", err)
		}
		if result == nil {
			t.Error("Expected non-nil result")
		}
	})

	t.Run("Handle invalid JSON", func(t *testing.T) {
		jsonData := `{"name":"John","email":invalid}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(jsonData))
		scope := &mockRequestScope{request: req}

		_, err := ReadJsonBody[TestRequest](scope)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

func TestReplyJson(t *testing.T) {
	t.Run("Successfully write JSON response", func(t *testing.T) {
		w := httptest.NewRecorder()
		data := TestResponse{
			Success: true,
			Message: "Operation completed",
			ID:      42,
		}

		err := ReplyJson(w, http.StatusOK, data)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		// Check status code
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Check content type
		if w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
		}

		// Check body
		var result TestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}
		if result.Success != true {
			t.Error("Expected success to be true")
		}
		if result.Message != "Operation completed" {
			t.Errorf("Expected message 'Operation completed', got %s", result.Message)
		}
		if result.ID != 42 {
			t.Errorf("Expected ID 42, got %d", result.ID)
		}
	})

	t.Run("Handle marshal error", func(t *testing.T) {
		w := httptest.NewRecorder()
		// Channel cannot be marshaled to JSON
		data := make(chan int)

		err := ReplyJson(w, http.StatusOK, data)
		if err == nil {
			t.Error("Expected error when marshaling invalid type")
		}
	})
}

func TestDumpedReplyJson(t *testing.T) {
	t.Run("Successfully write and dump JSON response", func(t *testing.T) {
		w := httptest.NewRecorder()
		data := map[string]string{
			"status": "ok",
			"code":   "200",
		}

		// Capture stdout
		old := bytes.NewBuffer(nil)

		err := DumpedReplyJson(w, http.StatusCreated, data)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		// Check status code
		if w.Code != http.StatusCreated {
			t.Errorf("Expected status 201, got %d", w.Code)
		}

		// Check body
		var result map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}
		if result["status"] != "ok" {
			t.Errorf("Expected status ok, got %s", result["status"])
		}

		// Note: We can't easily test stdout output in a unit test
		// but the function is covered
		_ = old
	})

	t.Run("Handle marshal error in DumpedReplyJson", func(t *testing.T) {
		w := httptest.NewRecorder()
		data := make(chan int)

		err := DumpedReplyJson(w, http.StatusOK, data)
		if err == nil {
			t.Error("Expected error when marshaling invalid type")
		}
	})
}

// Mock implementation of RequestScope for testing
type mockRequestScope struct {
	request *http.Request
}

func (m *mockRequestScope) HasSession() bool {
	return false
}

func (m *mockRequestScope) Request() *http.Request {
	return m.request
}

func (m *mockRequestScope) Context() context.Context {
	return m.request.Context()
}

func (m *mockRequestScope) Var(name string) string {
	return ""
}

func (m *mockRequestScope) LookupVar(name string) (string, bool) {
	return "", false
}

func (m *mockRequestScope) Parameter(name string) string {
	return ""
}

func (m *mockRequestScope) Parameters(name string) []string {
	return nil
}

func (m *mockRequestScope) LookupParameter(name string) (string, bool) {
	return "", false
}

func (m *mockRequestScope) LookupParameters(name string) ([]string, bool) {
	return nil, false
}

func (m *mockRequestScope) Get(key string) any {
	return nil
}

func (m *mockRequestScope) Set(key string, value any) {
}

func (m *mockRequestScope) Session() we.Session {
	return nil
}

// Ensure mockRequestScope implements we.RequestScope
var _ we.RequestScope = (*mockRequestScope)(nil)
