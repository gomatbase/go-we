// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"log"
	"net/http"
	"testing"
)

func TestAddRoutes(t *testing.T) {
	pathTree := newPathTree()

	// let's list the routes and ensure that is empty
	t.Run("Test PathTree Initialization", func(t *testing.T) {
		if routes := pathTree.ListRoutes(); len(routes) > 0 {
			t.Error("PathTree is initialized as non-empty", routes)
		}
	})

	t.Run("Test empty handler", func(t *testing.T) {
		if handler, _ := pathTree.getHandlerAndPathVariables("/"); handler != nil {
			t.Error("Non-Empty root handler")
		}
	})

	t.Run("Test adding a root handler", func(t *testing.T) {
		handler := new(Handler)
		log.Println("handler is", handler)
		if success, e := pathTree.addHandler("/", handler); !success {
			t.Error("Not able to add Handler", e.Error())
		} else {
			registeredHandler, variables := pathTree.getHandlerAndPathVariables("/")
			if registeredHandler == nil {
				t.Error("Unexpected null handler for root")
			} else {
				if registeredHandler != interface{}(handler) {
					t.Error("Unexpected registered handler for root", registeredHandler)
				} else if len(variables) > 0 {
					t.Error("Unexpected Path Variables found in endpoint", variables)
				}
			}
		}

		registeredHandler, _ := pathTree.getHandlerAndPathVariables("/something")
		if registeredHandler != nil {
			t.Error("Unexpectedly matched a handler for /something")
		}
	})

	t.Run("Test overloading a root handler", func(t *testing.T) {
		handler := new(Handler)
		if success, _ := pathTree.addHandler("/", handler); success {
			t.Error("Was able to  overload root handler")
		}
		registeredHandler, variables := pathTree.getHandlerAndPathVariables("/")
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
		handler := func(w http.ResponseWriter, context *RequestContext) {}

		if success, e := pathTree.addHandler("/something/somethingelse", &handler); !success {
			t.Error("Not able to add Handler", e.Error())
		}
		registeredHandler, variables := pathTree.getHandlerAndPathVariables("/something/somethingelse")
		if registeredHandler != &handler {
			t.Error("Unexpected registered handler for /something/somethingelse", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, _ = pathTree.getHandlerAndPathVariables("/something")
		if registeredHandler != nil {
			t.Error("Unexpected registered handler for /something", registeredHandler)
		}

	})

	t.Run("Test adding a variable handler", func(t *testing.T) {
		handler := func(w http.ResponseWriter, context *RequestContext) {}

		if success, e := pathTree.addHandler("/something/{somethingelse}", &handler); !success {
			t.Error("Not able to add Handler", e.Error())
		}

		// the static handler should take precendence
		registeredHandler, variables := pathTree.getHandlerAndPathVariables("/something/somethingelse")
		if registeredHandler == &handler {
			t.Error("Unexpected registered handler for /something/somethingelse", registeredHandler)
		} else if len(variables) > 0 {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		// should default to the variable handler
		registeredHandler, variables = pathTree.getHandlerAndPathVariables("/something/something")
		if registeredHandler != &handler {
			t.Error("Unexpected registered handler for /something/something", registeredHandler)
		} else if variables["somethingelse"] != "something" {
			t.Error("Unexpected Path Variables found in endpoint", variables)
		}

		registeredHandler, _ = pathTree.getHandlerAndPathVariables("/something")
		if registeredHandler != nil {
			t.Error("Unexpected registered handler for root", registeredHandler)
		}
	})

}
