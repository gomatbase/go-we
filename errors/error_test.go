// Copyright 2023 GOM. All rights reserved.
// Since 14/11/2023 By GOM
// Licensed under MIT License

package errors

import (
	"testing"
)

func TestWeError_Payload(t *testing.T) {
	err := NewPayload(500, "test", "something")
	if err.Payload() != "something" {
		t.Errorf("Error payload not set correctly. Expected \"something\", got \"%s\"", err.Payload())
	}
	err = New(500, "test")
	if err.Payload() != nil {
		t.Errorf("Error payload not set correctly. Expected nil, got %v", err.Payload())
	}
}

func TestWeError_Error(t *testing.T) {
	err := NewPayload(500, "test", "something")
	if err.Error() != "500: test" {
		t.Errorf("Error message not set correctly. Expected \"500: test\", got %s", err.Error())
	}
}

func TestWeError_WithPayload(t *testing.T) {
	err := NewPayload(500, "test", "something")
	if err.Payload() != "something" {
		t.Errorf("Error payload not set correctly. Expected \"something\", got \"%s\"", err.Payload())
	}
	err2 := err.WithPayload("something else")
	if err2.Payload() != "something else" {
		t.Errorf("Error payload not set correctly. Expected \"something else\", got \"%s\"", err2.Payload())
	}
	if err.Payload() != "something" {
		t.Errorf("Original error payload changed when generating a new error. Expected \"something\", got \"%s\"", err.Payload())
	}
	if err == err2 {
		t.Errorf("Original error and new error are the same")
	}
}

func TestWeError_StatusCode(t *testing.T) {
	err := New(500, "test")
	if err.StatusCode() != 500 {
		t.Errorf("Error status code not set correctly. Expected 500, got %d", err.StatusCode())
	}
}

func TestWeError_Is(t *testing.T) {
	err := New(500, "test")
	err2 := New(500, "test")
	if !err.Is(err2) {
		t.Errorf("Identical errors identified as different. %s vs %s", err.Error(), err2.Error())
	}
	err2 = NewPayload(500, "test", "something")
	if !err.Is(err2) {
		t.Errorf("Identical errors identified as different. %s vs %s", err.Error(), err2.Error())
	}
	err2 = New(500, "something else")
	if err.Is(err2) {
		t.Errorf("Non-Identical errors identified as identical. %s vs %s", err.Error(), err2.Error())
	}
	err2 = New(400, "test")
	if err.Is(err2) {
		t.Errorf("Non-Identical errors identified as identical. %s vs %s", err.Error(), err2.Error())
	}
	err2 = New(400, "something else")
	if err.Is(err2) {
		t.Errorf("Non-Identical errors identified as identical. %s vs %s", err.Error(), err2.Error())
	}
	err2 = err.WithPayload("something")
	if !err.Is(err2) {
		t.Errorf("Identical errors identified as different. %s vs %s", err.Error(), err2.Error())
	}
}
