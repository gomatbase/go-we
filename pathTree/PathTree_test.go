// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package pathTree

import (
	"log"
	"testing"
)

// Tests for PathTree endpoint adding.
func TestAddRoutes(t *testing.T) {
	pathTree := New[any]()

	// let's list the routes and ensure that is empty
	t.Run("Test PathTree Initialization", func(t *testing.T) {
		if routes := pathTree.ListRoutes(); len(routes) > 0 {
			t.Error("PathTree is initialized as non-empty", routes)
		}
	})

	t.Run("Test empty handler", func(t *testing.T) {
		if handler, _ := pathTree.Get("/"); handler != nil {
			t.Error("Non-Empty root handler")
		}
	})

	t.Run("Test adding a root handler", func(t *testing.T) {
		handler := new(any)
		log.Println("handler is", handler)
		if e := pathTree.Add("/", handler); e != nil {
			t.Error("Not able to add Handler", e)
		} else {
			registeredHandler, variables := pathTree.Get("/")
			if registeredHandler == nil {
				t.Error("Unexpected null handler for root")
			} else {
				if *registeredHandler != handler {
					t.Error("Unexpected registered handler for root", registeredHandler)
				} else if len(variables) > 0 {
					t.Error("Unexpected Path Variables found in endpoint", variables)
				}
			}
		}

		registeredHandler, _ := pathTree.Get("/something")
		if registeredHandler != nil {
			t.Error("Unexpectedly matched a handler for /something")
		}
	})

	t.Run("Test overloading a root handler", func(t *testing.T) {
		handler := new(any)
		if e := pathTree.Add("/", handler); e == nil {
			t.Error("Was able to  overload root handler")
		}
		registeredHandler, variables := pathTree.Get("/")
		if registeredHandler == nil {
			t.Error("Unexpected null handler for root")
		} else {
			if registeredHandler == any(handler) {
				t.Error("Unexpected registered handler for root", registeredHandler)
			} else if len(variables) > 0 {
				t.Error("Unexpected Path Variables found in endpoint", variables)
			}
		}
	})

	t.Run("Test adding a static handler", func(t *testing.T) {
		handler := new(any)

		if e := pathTree.Add("/something/somethingelse", &handler); e != nil {
			t.Error("Not able to add Handler", e)
		}
		registeredHandler, variables := pathTree.Get("/something/somethingelse")
		if *registeredHandler != &handler {
			t.Error("Unexpected registered handler for /something/somethingelse", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, _ = pathTree.Get("/something")
		if registeredHandler != nil {
			t.Error("Unexpected registered handler for /something", registeredHandler)
		}

	})

	t.Run("Test adding a variable handler", func(t *testing.T) {
		handler := new(any)

		if e := pathTree.Add("/something/{somethingelse}", handler); e != nil {
			t.Error("Not able to add Handler", e)
		}

		// the static handler should take precendence
		registeredHandler, variables := pathTree.Get("/something/somethingelse")
		if *registeredHandler == handler {
			t.Error("Unexpected registered handler for /something/somethingelse", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		// should default to the variable handler
		registeredHandler, variables = pathTree.Get("/something/something")
		if *registeredHandler != handler {
			t.Error("Unexpected registered handler for /something/something", registeredHandler)
		} else if variables["somethingelse"] != "something" {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, _ = pathTree.Get("/something")
		if registeredHandler != nil {
			t.Error("Unexpected registered handler for root", registeredHandler)
		}
	})

	t.Run("Test adding matching prefixed paths", func(t *testing.T) {
		handler1 := new(any)
		handler2 := new(any)

		if e := pathTree.Add("/something/somethingelse/uno", handler1); e != nil {
			t.Error("Not able to add Handler", e)
		}

		if e := pathTree.Add("/something/somethingelse/dos", handler2); e != nil {
			t.Error("Not able to add Handler", e)
		}

		registeredHandler, variables := pathTree.Get("/something/somethingelse/uno")
		if *registeredHandler != handler1 {
			t.Error("Unexpected registered handler for /something/somethingelse/uno", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, variables = pathTree.Get("/something/somethingelse/dos")
		if *registeredHandler != handler2 {
			t.Error("Unexpected registered handler for /something/somethingelse/dos", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}
	})

	t.Run("Test adding matching prefixed paths with variables", func(t *testing.T) {
		handler1 := new(any)
		handler2 := new(any)

		if e := pathTree.Add("/somethingwithvars/{somethingelse}/uno", handler1); e != nil {
			t.Error("Not able to add Handler", e)
		}

		if e := pathTree.Add("/somethingwithvars/{somethingelse}/dos", handler2); e != nil {
			t.Error("Not able to add Handler", e)
		}

		registeredHandler, variables := pathTree.Get("/somethingwithvars/somethingelse/uno")
		if *registeredHandler != handler1 {
			t.Error("Unexpected registered handler for /somethingwithvars/{somethingelse}/uno", registeredHandler)
		} else if len(variables) != 1 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, variables = pathTree.Get("/somethingwithvars/somethingelse/dos")
		if *registeredHandler != handler2 {
			t.Error("Unexpected registered handler for /somethingwithvars/{somethingelse}/dos", registeredHandler)
		} else if len(variables) != 1 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}
	})

	t.Run("Test single wildcard matches root", func(t *testing.T) {
		tree := New[string]()
		handler := "wildcard-handler"

		if err := tree.Add("/*", handler); err != nil {
			t.Error("Not able to add wildcard handler", err)
		}

		// Single wildcard should match root path
		result, variables := tree.Get("/")
		if result == nil {
			t.Error("Wildcard /* should match root path /")
		} else if *result != handler {
			t.Errorf("Expected handler %s, got %s", handler, *result)
		} else if len(variables) != 0 {
			t.Error("Unexpected variables for wildcard match", variables)
		}

		// Single wildcard should match single-level paths
		result, _ = tree.Get("/api")
		if result == nil {
			t.Error("Wildcard /* should match /api")
		}

		// Single wildcard should NOT match multi-level paths
		result, _ = tree.Get("/api/users")
		if result != nil {
			t.Error("Wildcard /* should NOT match /api/users")
		}
	})

	t.Run("Test double wildcard matches root", func(t *testing.T) {
		tree := New[string]()
		handler := "double-wildcard-handler"

		if err := tree.Add("/**", handler); err != nil {
			t.Error("Not able to add double wildcard handler", err)
		}

		// Double wildcard should match root path
		result, variables := tree.Get("/")
		if result == nil {
			t.Error("Double wildcard /** should match root path /")
		} else if *result != handler {
			t.Errorf("Expected handler %s, got %s", handler, *result)
		} else if len(variables) != 0 {
			t.Error("Unexpected variables for double wildcard match", variables)
		}

		// Double wildcard should match all paths
		testPaths := []string{"/api", "/api/users", "/api/users/123"}
		for _, path := range testPaths {
			result, _ = tree.Get(path)
			if result == nil {
				t.Errorf("Double wildcard /** should match %s", path)
			}
		}
	})

	t.Run("Test wildcard precedence with root", func(t *testing.T) {
		tree := New[string]()
		rootHandler := "root-exact"
		wildcardHandler := "wildcard"
		doubleWildcardHandler := "double-wildcard"

		// Add in reverse precedence order to ensure order doesn't matter
		if err := tree.Add("/**", doubleWildcardHandler); err != nil {
			t.Error("Failed to add /**", err)
		}
		if err := tree.Add("/*", wildcardHandler); err != nil {
			t.Error("Failed to add /*", err)
		}
		if err := tree.Add("/", rootHandler); err != nil {
			t.Error("Failed to add /", err)
		}

		// Exact match should win for root
		result, _ := tree.Get("/")
		if result == nil {
			t.Error("Expected match for /")
		} else if *result != rootHandler {
			t.Errorf("Expected exact match %s for /, got %s", rootHandler, *result)
		}

		// Single wildcard should win for single-level paths
		result, _ = tree.Get("/api")
		if result == nil {
			t.Error("Expected match for /api")
		} else if *result != wildcardHandler {
			t.Errorf("Expected wildcard match %s for /api, got %s", wildcardHandler, *result)
		}

		// Double wildcard should match multi-level paths
		result, _ = tree.Get("/api/users")
		if result == nil {
			t.Error("Expected match for /api/users")
		} else if *result != doubleWildcardHandler {
			t.Errorf("Expected double wildcard match %s for /api/users, got %s", doubleWildcardHandler, *result)
		}
	})

	t.Run("Test wildcard with specific paths", func(t *testing.T) {
		tree := New[string]()
		apiExactHandler := "api-exact"
		apiWildcardHandler := "api-wildcard"
		doubleWildcardHandler := "double-wildcard"

		tree.Add("/**", doubleWildcardHandler)
		tree.Add("/api", apiExactHandler)
		tree.Add("/api/*", apiWildcardHandler)

		// Root should match double wildcard
		result, _ := tree.Get("/")
		if result == nil || *result != doubleWildcardHandler {
			t.Error("Expected /** to match /")
		}

		// /api should match exact
		result, _ = tree.Get("/api")
		if result == nil || *result != apiExactHandler {
			t.Error("Expected /api exact match")
		}

		// /api/users should match /api/*
		result, _ = tree.Get("/api/users")
		if result == nil || *result != apiWildcardHandler {
			t.Error("Expected /api/* to match /api/users")
		}

		// /api/users/123 should match /**
		result, _ = tree.Get("/api/users/123")
		if result == nil || *result != doubleWildcardHandler {
			t.Error("Expected /** to match /api/users/123")
		}

		// /other should match /**
		result, _ = tree.Get("/other")
		if result == nil || *result != doubleWildcardHandler {
			t.Error("Expected /** to match /other")
		}
	})

}
