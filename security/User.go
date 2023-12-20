// Copyright 2023 GOM. All rights reserved.
// Since 13/11/2023 By GOM
// Licensed under MIT License

package security

type User struct {
	Realm    string   `json:"realm"`
	Password string   `json:"-"`
	Username string   `json:"username"`
	Scopes   []string `json:"scopes"`
	Origin   string   `json:"origin"`
	OriginId string   `json:"originId"`
	Active   bool     `json:"active"`
	Data     any
}
