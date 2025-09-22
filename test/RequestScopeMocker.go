// Copyright 2023 GOM. All rights reserved.
// Since 15/11/2023 By GOM
// Licensed under MIT License

package test

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gomatbase/go-we"
)

type body struct {
	buffer *bytes.Buffer
}

func (b *body) Read(p []byte) (n int, err error) {
	if b.buffer == nil {
		return 0, io.EOF
	}
	return b.buffer.Read(p)
}

func (b *body) Close() error {
	return nil
}

type RequestScopeMocker interface {
	we.RequestScope
	SetHeader(string, string)
	SetVariables(map[string]string)
	SetBody([]byte)
}

type mockedRequestScope struct {
	request    *http.Request
	variables  map[string]string
	attributes map[string]any
	session    *we.Session
}

func (m *mockedRequestScope) HasSession() bool {
	return m.session != nil
}

func (m *mockedRequestScope) Request() *http.Request {
	return m.request
}

func (m *mockedRequestScope) Var(name string) string {
	if m.variables == nil {
		return ""
	}
	return m.variables[name]
}

func (m *mockedRequestScope) LookupVar(name string) (string, bool) {
	if m.variables == nil {
		return "", false
	}
	value, found := m.variables[name]
	return value, found
}

func (m *mockedRequestScope) Parameter(s string) string {
	return m.request.URL.Query().Get(s)
}

func (m *mockedRequestScope) Parameters(s string) []string {
	return m.request.URL.Query()[s]
}

func (m *mockedRequestScope) LookupParameter(s string) (string, bool) {
	if values := m.request.URL.Query()[s]; len(values) > 0 {
		return values[0], true
	}
	return "", false
}

func (m *mockedRequestScope) LookupParameters(s string) ([]string, bool) {
	if values := m.request.URL.Query()[s]; len(values) > 0 {
		return values, true
	}
	return nil, false
}

func (m *mockedRequestScope) Get(name string) any {
	return m.attributes[name]
}

func (m *mockedRequestScope) Set(name string, value any) {
	m.attributes[name] = value
}

func (m *mockedRequestScope) GetFromSession(name string) any {
	if m.session == nil {
		return nil
	}
	return m.session.Attributes[name]
}

func (m *mockedRequestScope) SetInSession(name string, value any) {
	if m.session == nil {
		m.session = &we.Session{Attributes: make(map[string]any)}
	}
	m.session.Attributes[name] = value
}

func (m *mockedRequestScope) SetHeader(key string, value string) {
	m.request.Header.Set(key, value)
}

func (m *mockedRequestScope) SetVariables(variables map[string]string) {
	m.variables = variables
}

func (m *mockedRequestScope) SetBody(content []byte) {
	if content == nil {
		m.request.Body = nil
	} else {
		m.request.ContentLength = int64(len(content))
		m.request.Body.(*body).buffer = bytes.NewBuffer(content)
	}
}

func MockedRequestScope(method, rawUrl string) RequestScopeMocker {
	parsedUrl, e := url.Parse(rawUrl)
	if e != nil {
		panic(e)
	}
	host := strings.Split(parsedUrl.Host, ":")[0]

	return &mockedRequestScope{
		attributes: make(map[string]any),
		variables:  make(map[string]string),
		request: &http.Request{
			Method:           method,
			URL:              parsedUrl,
			Proto:            "",
			ProtoMajor:       0,
			ProtoMinor:       0,
			Header:           http.Header{"Host": []string{host}},
			Body:             &body{},
			ContentLength:    0,
			TransferEncoding: nil,
			Close:            false,
			Host:             parsedUrl.Host,
		},
	}
}
