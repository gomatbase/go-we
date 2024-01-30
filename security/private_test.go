// Copyright 2023 GOM. All rights reserved.
// Since 28/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"testing"
)

func TestIfNil(t *testing.T) {
	if v := ifNil(nil, "value"); v != "value" {
		t.Errorf("expected default value to return instead: %v", v)
	}
	if v := ifNil("original", "value"); v != "original" {
		t.Errorf("expected original value to return instead: %v", v)
	}
}
