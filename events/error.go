// Copyright 2023 GOM. All rights reserved.
// Since 12/11/2023 By GOM
// Licensed under MIT License

package events

import (
	"fmt"
)

// Event Categories for flow control events
const (
	RequestFlow  = 1
	Interruption = 2
	Redirection  = 3
)

// WeEvent is the interface for events that are meant to be used both as error as well as a flow control event.
// It always has an http status associated as it will potentially be used to interrupt the flow and return a response.
// The attribute is a string that the engine may use to set headers or attributes in requests and responses, while payload
// is a set of bytes and mime type containing a response to be given to the client in case of error or interruption
// events. when implementing (and using) custom WeEvent objects, these two rules should always be taken into consideration.
type WeEvent interface {
	// Error returns the event message prepended by the status code
	error
	// StatusCode returns the status code associated to the event
	StatusCode() int
	// Payload returns the payload carried by the event. Payloads have data that may be used when producing a response
	Payload() *Payload
	// Attribute returns the attribute carried by the event. Attributes have data that may be used when processing the error/event
	Attribute() string
	// Category returns the range in which http status code of the event falls into (basically , the first digit of the three digit http status code)
	Category() int
	// WithPayload returns a new identical error with a payload of the given content type and content
	WithPayload(string, []byte) WeEvent
	// WithAttribute returns a new identical event with the given attribute
	WithAttribute(string) WeEvent
	// Is checks if the given error is an event identical to this one. An error is considered identical  to the event if
	// it is also an event and has exactly the same status code and message, disregarding the payload and attribute
	Is(error) bool
}

// New creates a new we error with the given status code and message with no payload and no attribute
func New(statusCode int, message string) WeEvent {
	return NewPayload(statusCode, message, nil)
}

// NewPayload creates a new we error with the given status code, message and payload
func NewPayload(statusCode int, message string, payload *Payload) WeEvent {
	return &weEvent{
		category:   statusCode / 100,
		statusCode: statusCode,
		message:    message,
		payload:    payload,
	}
}

// weEvent is a WeEvent implementation
type weEvent struct {
	statusCode int
	category   int
	message    string
	payload    *Payload
	attribute  string
}

// Payload holds the content and mimetype of a response that should be sent when handling the event
type Payload struct {
	ContentTypeHint string
	Content         []byte
}

func (wee *weEvent) Error() string {
	return fmt.Sprintf("%d: %s", wee.statusCode, wee.message)
}

func (wee *weEvent) StatusCode() int {
	return wee.statusCode
}

func (wee *weEvent) Payload() *Payload {
	return wee.payload
}

func (wee *weEvent) Attribute() string {
	return wee.attribute
}

func (wee *weEvent) Category() int {
	return wee.category
}

func (wee *weEvent) WithPayload(contentTypeHint string, content []byte) WeEvent {
	return &weEvent{
		statusCode: wee.statusCode,
		message:    wee.message,
		category:   wee.category,
		attribute:  wee.attribute,
		payload: &Payload{
			ContentTypeHint: contentTypeHint,
			Content:         content,
		},
	}
}

func (wee *weEvent) WithAttribute(attribute string) WeEvent {
	return &weEvent{
		statusCode: wee.statusCode,
		message:    wee.message,
		category:   wee.category,
		payload:    wee.payload,
		attribute:  attribute,
	}
}

func (wee *weEvent) Is(err error) bool {
	if wee == err {
		return true
	}
	if event, ok := err.(*weEvent); ok {
		return wee.statusCode == event.StatusCode() && wee.message == event.message
	}
	return false
}
