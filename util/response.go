// Copyright 2023 GOM. All rights reserved.
// Since 24/10/2023 By GOM
// Licensed under MIT License

package util

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func replyJson(w http.ResponseWriter, status int, value any) ([]byte, error) {
	if body, e := json.Marshal(value); e == nil {
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(status)
		if _, e = w.Write(body); e != nil {
			return nil, e
		}
		return body, nil
	} else {
		return nil, e
	}
}

func ReplyJson(w http.ResponseWriter, status int, value any) error {
	_, e := replyJson(w, status, value)
	return e
}

func DumpedReplyJson(w http.ResponseWriter, status int, value any) error {
	if body, e := replyJson(w, status, value); e == nil {
		fmt.Println("response: code:", status, ", body:", string(body))
	} else {
		return e
	}

	return nil
}
