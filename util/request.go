// Copyright 2023 GOM. All rights reserved.
// Since 24/10/2023 By GOM
// Licensed under MIT License

package util

import (
	"encoding/json"
	"io"

	"github.com/gomatbase/go-we"
)

func ReadJsonBody[T any](scope we.RequestScope) (*T, error) {
	result := new(T)
	if e := json.NewDecoder(scope.Request().Body).Decode(result); e != nil && e != io.EOF {
		return nil, e
	}
	return result, nil
}
