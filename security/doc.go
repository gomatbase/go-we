// Copyright 2025 GOM. All rights reserved.
// Since 13/01/2025 By GOM
// Licensed under MIT License

// Package security provides a simple way to authenticate and authorize access to content provided through go-we using
// a Filter that implements standard authentication mechanisms.
//
// It currently supports Basic authentication, bearer tokens, login forms and SSO (with OAuth2).
//
// Usage is simplified resorting to builders to configure the security filter which can then be added to a go-we
// engine using we.New().AddFilter(security.New().Build()).
//
// See examples for concrete usage.
package security
