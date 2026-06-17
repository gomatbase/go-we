// Copyright 2023-2026 GOM. All rights reserved.
// Since 14/11/2023 By GOM
// Licensed under MIT License

package events

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWeEvent_Payload(t *testing.T) {
	event := NewPayload(500, "test", &Payload{"text/plain", []byte("something")})
	if string(event.Payload().Content) != "something" {
		t.Errorf("Event payload not set correctly. Expected \"something\", got \"%s\"", event.Payload())
	}
	event = New(500, "test")
	if event.Payload() != nil {
		t.Errorf("Event payload not set correctly. Expected nil, got %v", event.Payload())
	}
}

func TestWeEvent_Error(t *testing.T) {
	event := NewPayload(500, "test", &Payload{"text/plain", []byte("something")})
	if event.Error() != "500: test" {
		t.Errorf("Event error message not set correctly. Expected \"500: test\", got %s", event.Error())
	}
}

func TestWeEvent_WithPayload(t *testing.T) {
	event := NewPayload(500, "test", &Payload{"text/plain", []byte("something")})
	if string(event.Payload().Content) != "something" {
		t.Errorf("Event payload not set correctly. Expected \"something\", got \"%s\"", event.Payload())
	}
	event2 := event.WithPayload("text/plain", []byte("something else"))
	if string(event2.Payload().Content) != "something else" {
		t.Errorf("Event payload not set correctly. Expected \"something else\", got \"%s\"", event2.Payload())
	}
	if string(event.Payload().Content) != "something" {
		t.Errorf("Original event payload changed when generating a new event. Expected \"something\", got \"%s\"", event.Payload())
	}
	if event == event2 {
		t.Errorf("Original event and new event are the same")
	}
	if !event.Is(event2) {
		t.Errorf("Original event and new event are not identical")
	}
}

func TestWeEvent_StatusCode(t *testing.T) {
	event := New(500, "test")
	if event.StatusCode() != 500 {
		t.Errorf("Event status code not set correctly. Expected 500, got %d", event.StatusCode())
	}
}

func TestWeEvent_Is(t *testing.T) {
	event := New(500, "test")
	event2 := New(500, "test")
	if !event.Is(event) {
		t.Error("Same event not recognized as Identical")
	}
	if !event.Is(event2) {
		t.Errorf("Identical events identified as different. %s vs %s", event.Error(), event2.Error())
	}
	event2 = NewPayload(500, "test", &Payload{"text/plain", []byte("something")})
	if !event.Is(event2) {
		t.Errorf("Identical events identified as different. %s vs %s", event.Error(), event2.Error())
	}
	event2 = New(500, "something else")
	if event.Is(event2) {
		t.Errorf("Non-Identical events identified as identical. %s vs %s", event.Error(), event2.Error())
	}
	event2 = New(400, "test")
	if event.Is(event2) {
		t.Errorf("Non-Identical events identified as identical. %s vs %s", event.Error(), event2.Error())
	}
	event2 = New(400, "something else")
	if event.Is(event2) {
		t.Errorf("Non-Identical events identified as identical. %s vs %s", event.Error(), event2.Error())
	}
	event2 = event.WithPayload("text/plain", []byte("something"))
	if !event.Is(event2) {
		t.Errorf("Identical events identified as different. %s vs %s", event.Error(), event2.Error())
	}
	if event.Is(errors.New(event.Error())) {
		t.Error("Non we event error identified as identical")
	}
}

func TestWeEvent_Attribute(t *testing.T) {
	event := New(404, "not found")

	// Test default attribute
	if event.Attribute() != "" {
		t.Errorf("Expected empty attribute for new event, got %s", event.Attribute())
	}

	// Test WithAttribute
	event2 := event.WithAttribute("user-error")
	if event2.Attribute() != "user-error" {
		t.Errorf("Expected attribute to be 'user-error', got %s", event2.Attribute())
	}

	// Verify original event unchanged
	if event.Attribute() != "" {
		t.Errorf("Original event should have empty attribute, got %s", event.Attribute())
	}

	// Verify new event is identical (same status/message)
	if !event.Is(event2) {
		t.Error("Event with attribute should be identical to original")
	}
}

func TestWeEvent_Category(t *testing.T) {
	tests := []struct {
		statusCode int
		category   EventFlowCategory
	}{
		{100, 1}, // Informational
		{200, 2}, // Success
		{201, 2},
		{300, 3}, // Redirection
		{302, 3},
		{400, 4}, // Client Error
		{404, 4},
		{500, 5}, // Server Error
		{503, 5},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Status %d", tt.statusCode), func(t *testing.T) {
			event := New(tt.statusCode, "test message")
			if event.Category() != tt.category {
				t.Errorf("Expected category %d for status %d, got %d",
					tt.category, tt.statusCode, event.Category())
			}
		})
	}
}

func TestHandleFlowEvent(t *testing.T) {
	t.Run("non-WeEvent error returns false Unknown nil", func(t *testing.T) {
		w := httptest.NewRecorder()
		handled, category, event := HandleFlowEvent(w, errors.New("plain error"))
		if handled {
			t.Error("Expected handled to be false")
		}
		if category != Unknown {
			t.Errorf("Expected category Unknown (0), got %d", category)
		}
		if event != nil {
			t.Error("Expected event to be nil")
		}
	})

	t.Run("Interruption with payload sets Content-type status and body", func(t *testing.T) {
		w := httptest.NewRecorder()
		payload := &Payload{"application/json", []byte(`{"error":"bad"}`)}
		e := NewPayload(200, "ok", payload)
		handled, category, event := HandleFlowEvent(w, e)
		if !handled {
			t.Error("Expected handled to be true")
		}
		if category != Interruption {
			t.Errorf("Expected category Interruption (2), got %d", category)
		}
		if event == nil {
			t.Fatal("Expected event to be non-nil")
		}
		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		if ct := w.Header().Get("Content-type"); ct != "application/json" {
			t.Errorf("Expected Content-type 'application/json', got '%s'", ct)
		}
		if body := w.Body.String(); body != `{"error":"bad"}` {
			t.Errorf("Expected body '{\"error\":\"bad\"}', got '%s'", body)
		}
	})

	t.Run("Interruption without payload sets only status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		e := New(204, "no content")
		handled, category, event := HandleFlowEvent(w, e)
		if !handled {
			t.Error("Expected handled to be true")
		}
		if category != Interruption {
			t.Errorf("Expected category Interruption (2), got %d", category)
		}
		if event == nil {
			t.Fatal("Expected event to be non-nil")
		}
		resp := w.Result()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", resp.StatusCode)
		}
		if ct := w.Header().Get("Content-type"); ct != "" {
			t.Errorf("Expected no Content-type header, got '%s'", ct)
		}
		if body := w.Body.String(); body != "" {
			t.Errorf("Expected empty body, got '%s'", body)
		}
	})

	t.Run("Redirection sets Location header and status code", func(t *testing.T) {
		w := httptest.NewRecorder()
		e := New(302, "found").WithAttribute("https://example.com/redirect")
		handled, category, event := HandleFlowEvent(w, e)
		if !handled {
			t.Error("Expected handled to be true")
		}
		if category != Redirection {
			t.Errorf("Expected category Redirection (3), got %d", category)
		}
		if event == nil {
			t.Fatal("Expected event to be non-nil")
		}
		resp := w.Result()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("Expected status 302, got %d", resp.StatusCode)
		}
		if loc := w.Header().Get("Location"); loc != "https://example.com/redirect" {
			t.Errorf("Expected Location 'https://example.com/redirect', got '%s'", loc)
		}
	})

	t.Run("RequestFlow category returns false with event", func(t *testing.T) {
		w := httptest.NewRecorder()
		e := New(100, "continue")
		handled, category, event := HandleFlowEvent(w, e)
		if handled {
			t.Error("Expected handled to be false")
		}
		if category != RequestFlow {
			t.Errorf("Expected category RequestFlow (1), got %d", category)
		}
		if event == nil {
			t.Fatal("Expected event to be non-nil")
		}
	})

	t.Run("Client error category returns false with event", func(t *testing.T) {
		w := httptest.NewRecorder()
		e := New(404, "not found")
		handled, category, event := HandleFlowEvent(w, e)
		if handled {
			t.Error("Expected handled to be false")
		}
		if category != EventFlowCategory(4) {
			t.Errorf("Expected category 4, got %d", category)
		}
		if event == nil {
			t.Fatal("Expected event to be non-nil")
		}
	})

	t.Run("Server error category returns false with event", func(t *testing.T) {
		w := httptest.NewRecorder()
		e := New(500, "internal server error")
		handled, category, event := HandleFlowEvent(w, e)
		if handled {
			t.Error("Expected handled to be false")
		}
		if category != EventFlowCategory(5) {
			t.Errorf("Expected category 5, got %d", category)
		}
		if event == nil {
			t.Fatal("Expected event to be non-nil")
		}
	})
}
