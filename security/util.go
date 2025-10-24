// Copyright 2024 GOM. All rights reserved.
// Since 30/01/2024 By GOM
// Licensed under MIT License

package security

import "github.com/gomatbase/go-we"

func GetUser(scope we.RequestScope) *User {
	if user, isType := scope.Get(UserAttributeName).(*User); isType {
		return user
	}
	return nil
}
