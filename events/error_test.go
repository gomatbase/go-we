// Copyright 2023 GOM. All rights reserved.
// Since 14/11/2023 By GOM
// Licensed under MIT License

package events

import (
	"errors"
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
