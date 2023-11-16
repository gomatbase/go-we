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
		if success, e := pathTree.Add("/", handler); !success {
			t.Error("Not able to add Handler", e)
		} else {
			registeredHandler, variables := pathTree.Get("/")
			if registeredHandler == nil {
				t.Error("Unexpected null handler for root")
			} else {
				if registeredHandler != handler {
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
		if success, _ := pathTree.Add("/", handler); success {
			t.Error("Was able to  overload root handler")
		}
		registeredHandler, variables := pathTree.Get("/")
		if registeredHandler == nil {
			t.Error("Unexpected null handler for root")
		} else {
			if registeredHandler == interface{}(handler) {
				t.Error("Unexpected registered handler for root", registeredHandler)
			} else if len(variables) > 0 {
				t.Error("Unexpected Path Variables found in endpoint", variables)
			}
		}
	})

	t.Run("Test adding a static handler", func(t *testing.T) {
		handler := new(any)

		if success, e := pathTree.Add("/something/somethingelse", &handler); !success {
			t.Error("Not able to add Handler", e)
		}
		registeredHandler, variables := pathTree.Get("/something/somethingelse")
		if registeredHandler != &handler {
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

		if success, e := pathTree.Add("/something/{somethingelse}", &handler); !success {
			t.Error("Not able to add Handler", e)
		}

		// the static handler should take precendence
		registeredHandler, variables := pathTree.Get("/something/somethingelse")
		if registeredHandler == &handler {
			t.Error("Unexpected registered handler for /something/somethingelse", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		// should default to the variable handler
		registeredHandler, variables = pathTree.Get("/something/something")
		if registeredHandler != &handler {
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

		if success, e := pathTree.Add("/something/somethingelse/uno", &handler1); !success {
			t.Error("Not able to add Handler", e)
		}

		if success, e := pathTree.Add("/something/somethingelse/dos", &handler2); !success {
			t.Error("Not able to add Handler", e)
		}

		registeredHandler, variables := pathTree.Get("/something/somethingelse/uno")
		if registeredHandler != &handler1 {
			t.Error("Unexpected registered handler for /something/somethingelse/uno", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, variables = pathTree.Get("/something/somethingelse/dos")
		if registeredHandler != &handler2 {
			t.Error("Unexpected registered handler for /something/somethingelse/dos", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}
	})

	t.Run("Test adding matching prefixed paths with variables", func(t *testing.T) {
		handler1 := new(any)
		handler2 := new(any)

		if success, e := pathTree.Add("/somethingwithvars/{somethingelse}/uno", &handler1); !success {
			t.Error("Not able to add Handler", e)
		}

		if success, e := pathTree.Add("/somethingwithvars/{somethingelse}/dos", &handler2); !success {
			t.Error("Not able to add Handler", e)
		}

		registeredHandler, variables := pathTree.Get("/somethingwithvars/somethingelse/uno")
		if registeredHandler != &handler1 {
			t.Error("Unexpected registered handler for /somethingwithvars/{somethingelse}/uno", registeredHandler)
		} else if len(variables) != 1 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, variables = pathTree.Get("/somethingwithvars/somethingelse/dos")
		if registeredHandler != &handler2 {
			t.Error("Unexpected registered handler for /somethingwithvars/{somethingelse}/dos", registeredHandler)
		} else if len(variables) != 1 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}
	})

}
