// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package filters

import (
	"net/http"
	"testing"
	"time"

	we "github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
	"github.com/gomatbase/go-we/test"
)

func TestRateLimiter(t *testing.T) {
	t.Run("Test_default_configuration", func(t *testing.T) {
		filter := RateLimiter().Build()
		if filter == nil {
			t.Error("expected filter, got nil")
		}
	})

	t.Run("Test_allows_requests_within_limit", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(5).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")

		// Should allow burst requests
		for i := 0; i < 5; i++ {
			err := filter.Filter(http.Header{}, scope)
			if err != nil {
				t.Errorf("request %d should be allowed: %v", i+1, err)
			}
		}
	})

	t.Run("Test_rejects_requests_exceeding_burst", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(3).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")

		// Use up the burst
		for i := 0; i < 3; i++ {
			filter.Filter(http.Header{}, scope)
		}

		// Next request should be rejected
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected error when exceeding burst")
		}

		weEvent, ok := err.(events.WeEvent)
		if !ok {
			t.Errorf("expected WeEvent, got %T", err)
		}

		if weEvent.StatusCode() != http.StatusTooManyRequests {
			t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, weEvent.StatusCode())
		}
	})

	t.Run("Test_token_refill_over_time", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(2).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")

		// Use up the burst
		filter.Filter(http.Header{}, scope)
		filter.Filter(http.Header{}, scope)

		// Next request should fail
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected burst to be exhausted")
		}

		// Wait for token refill (100ms for 1 token at 10 RPS)
		time.Sleep(110 * time.Millisecond)

		// Should now succeed
		err = filter.Filter(http.Header{}, scope)
		if err != nil {
			t.Errorf("unexpected error after refill: %v", err)
		}
	})

	t.Run("Test_exempt_paths", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(1).
			ExemptPaths("/health", "/metrics").
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/health")

		// All requests to exempt path should succeed
		for i := 0; i < 100; i++ {
			err := filter.Filter(http.Header{}, scope)
			if err != nil {
				t.Errorf("request %d to exempt path should succeed: %v", i+1, err)
			}
		}
	})

	t.Run("Test_multiple_identifiers", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(2).
			Build()

		// First identifier (IP 1)
		scope1 := test.MockedRequestScope("GET", "http://localhost/api")
		scope1.Request().RemoteAddr = "192.168.1.1:12345"

		// Second identifier (IP 2)
		scope2 := test.MockedRequestScope("GET", "http://localhost/api")
		scope2.Request().RemoteAddr = "192.168.1.2:12345"

		// Both should be able to use their burst
		filter.Filter(http.Header{}, scope1)
		filter.Filter(http.Header{}, scope1)
		filter.Filter(http.Header{}, scope2)
		filter.Filter(http.Header{}, scope2)

		// Both should be limited on next request
		err1 := filter.Filter(http.Header{}, scope1)
		if err1 == nil {
			t.Error("expected scope1 to be rate limited")
		}

		err2 := filter.Filter(http.Header{}, scope2)
		if err2 == nil {
			t.Error("expected scope2 to be rate limited")
		}
	})

	t.Run("Test_custom_identifier", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(2).
			Identifier(func(scope we.RequestScope) string {
				// Custom identifier: always return same ID for testing
				return "test-user"
			}).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")

		// Use burst
		filter.Filter(http.Header{}, scope)
		filter.Filter(http.Header{}, scope)

		// Next should be limited
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected rate limiting based on custom identifier")
		}
	})

	t.Run("Test_x_forwarded_for_header", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(2).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")
		scope.Request().Header.Set("X-Forwarded-For", "203.0.113.1")

		// Use burst
		filter.Filter(http.Header{}, scope)
		filter.Filter(http.Header{}, scope)

		// Next should be limited
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected rate limiting based on X-Forwarded-For")
		}
	})

	t.Run("Test_x_real_ip_header", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(2).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")
		scope.Request().Header.Set("X-Real-IP", "203.0.113.2")

		// Use burst
		filter.Filter(http.Header{}, scope)
		filter.Filter(http.Header{}, scope)

		// Next should be limited
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected rate limiting based on X-Real-IP")
		}
	})

	t.Run("Test_panic_on_invalid_rps", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid RPS")
			}
		}()

		RateLimiter().RequestsPerSecond(0)
	})

	t.Run("Test_panic_on_negative_rps", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for negative RPS")
			}
		}()

		RateLimiter().RequestsPerSecond(-1)
	})

	t.Run("Test_panic_on_invalid_burst", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for invalid burst")
			}
		}()

		RateLimiter().Burst(0)
	})

	t.Run("Test_panic_on_negative_burst", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for negative burst")
			}
		}()

		RateLimiter().Burst(-1)
	})

	t.Run("Test_panic_on_no_exempt_paths", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for no exempt paths")
			}
		}()

		RateLimiter().ExemptPaths()
	})

	t.Run("Test_panic_on_empty_exempt_path", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for empty exempt path")
			}
		}()

		RateLimiter().ExemptPaths("", "/valid")
	})

	t.Run("Test_panic_on_nil_identifier", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for nil identifier")
			}
		}()

		RateLimiter().Identifier(nil)
	})

	t.Run("Test_rate_limit_returns_429", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(1).
			Burst(1).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")

		// Use the burst
		filter.Filter(http.Header{}, scope)

		// Next request should get 429
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Fatal("expected rate limit error")
		}

		weEvent, ok := err.(events.WeEvent)
		if !ok {
			t.Fatalf("expected WeEvent, got %T", err)
		}

		if weEvent.StatusCode() != http.StatusTooManyRequests {
			t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, weEvent.StatusCode())
		}
	})

	t.Run("Test_high_rps_allows_many_requests", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(1000).
			Burst(100).
			Build()

		scope := test.MockedRequestScope("GET", "http://localhost/api")

		// Should allow 100 requests (burst)
		for i := 0; i < 100; i++ {
			err := filter.Filter(http.Header{}, scope)
			if err != nil {
				t.Errorf("request %d should be allowed: %v", i+1, err)
			}
		}

		// 101st should fail
		err := filter.Filter(http.Header{}, scope)
		if err == nil {
			t.Error("expected burst to be exhausted")
		}
	})

	t.Run("Test_multiple_exempt_paths", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(1).
			Burst(1).
			ExemptPaths("/health", "/metrics", "/ready").
			Build()

		for _, path := range []string{"/health", "/metrics", "/ready"} {
			scope := test.MockedRequestScope("GET", "http://localhost"+path)

			// All requests should succeed
			for i := 0; i < 10; i++ {
				err := filter.Filter(http.Header{}, scope)
				if err != nil {
					t.Errorf("request to %s should be allowed: %v", path, err)
				}
			}
		}
	})

	t.Run("Test_non_exempt_path_is_limited", func(t *testing.T) {
		filter := RateLimiter().
			RequestsPerSecond(10).
			Burst(1).
			ExemptPaths("/health").
			Build()

		scopeNormal := test.MockedRequestScope("GET", "http://localhost/api")
		scopeExempt := test.MockedRequestScope("GET", "http://localhost/health")

		// Health check should work
		filter.Filter(http.Header{}, scopeExempt)
		filter.Filter(http.Header{}, scopeExempt)

		// Normal endpoint should be limited
		filter.Filter(http.Header{}, scopeNormal)
		err := filter.Filter(http.Header{}, scopeNormal)
		if err == nil {
			t.Error("expected normal path to be rate limited")
		}
	})
}
