// Copyright 2023 GOM. All rights reserved.
// Since 13/11/2023 By GOM
// Licensed under MIT License

package security

type User struct {
	Realm      string   `json:"realm"`
	Id         string   `json:"id"`
	Password   string   `json:"-"`
	Username   string   `json:"username"`
	Email      string   `json:"email"`
	Scopes     []string `json:"scope"`
	Authorized int      `json:"auth_time"`
	Origin     string   `json:"origin"`
	Active     bool     `json:"active"`
}
