// Copyright 2023 GOM. All rights reserved.
// Since 24/10/2023 By GOM
// Licensed under MIT License

package util

import (
	"encoding/json"
	"net/http"
)

func ReplyJson(w http.ResponseWriter, status int, value interface{}) error {
	if body, e := json.Marshal(value); e == nil {
		w.WriteHeader(status)
		w.Header().Add("Content-type", "application/json")
		if _, e = w.Write(body); e != nil {
			return e
		}
	} else {
		return e
	}

	return nil
}
