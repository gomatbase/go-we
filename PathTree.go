// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	VALUE = iota
	PATH_VARIABLE
	WILDCARD
	DOUBLE_WILDCARD
	PATH_PART
)

var (
	// Regular expression to validate valid endpoints that can be added to the path tree. It supports standard url
	// endpoints, path variables identified by {} brackets and standard alpha numeric names, single path node wildcards
	// and multi-node matching wildcards
	validPathExpression = regexp.MustCompile("^(/|(/(([a-zA-Z0-9_.\\-@~]|%[0-9a-fA-f]{2})+|{[a-zA-Z0-9]+}|\\*\\*?))*/?)$")
)

// A node in the pathTree. Each node represents an element in the path, containing a matching value for the path tree
// an object associated to the node (which makes it a terminating node, i.e. a matching path, and all the down path
// children for the current element, aggregated by type of matchers. These will are the children elements (plain
// path elements), variables (elements representing variables), if there is any child wildcard (any path element may
// match it) or double wildcard children (any combination of path elements will match it.
type treePathNode struct {
	// the value of the current element. this may be a wildcard, double wildcard, a valid path segment  which should be
	// matched exactly or a variable name, if the current node represents a variable. the type of the node is defined
	// by the type of child that the node represents, meaning that the parent node defines what the value the the child
	// node represents, depending on which category of children in the parent node the child node falls into.
	value string

	// helper flag identifying the current node as a path variable node
	pathVariable bool

	// helper flag identifying if the the current node has any children under any of the child categories
	hasChildren bool

	// The handler for this node. If present it tags the current node as a terminating node, meaning that a match ending
	// in this node is a successful match. If not present, a match ending in this node is not successful, and hence,
	// not matched.
	handler interface{}

	// Any simple child path elements that may have matches further down
	children []*treePathNode

	// Any variable child path elements to match further down the path
	variables []*treePathNode

	// A single wildcard child. If present, it allows matching further down any single child element
	wildCard *treePathNode

	// A double wildcard child. If present, it allows matching any number of of child path elements.
	doubleWildcard *treePathNode
}

// A path matching tree. it holds a single root node, not used for matching, but to categorize matches for the first
// path element
type pathTree struct {
	// the root node
	root *treePathNode
}

// Create a new path tree node, initialized with a value and no children
func newTreeNode(name string) *treePathNode {
	result := new(treePathNode)
	result.value = name
	result.children = make([]*treePathNode, 0)
	result.variables = make([]*treePathNode, 0)
	return result
}

// Create a new path tree, initializing the dummy root node.
func newPathTree() *pathTree {
	result := new(pathTree)
	result.root = newTreeNode("root")
	return result
}

// processes a path element for use as tree node value, stripping curly brackets from path variable elements so the
// variable name can be used as the node value, and returns the type of path element the name parameter represents
// (VALUE, PATH_VARIABLE, WILDCARD or DOUBLE_WILDCARD)
func stripPart(name string) (string, int) {
	firstCharacter := name[0]
	partType := VALUE

	// based on the valid path values that the path tree accepts (enforced through through the validPathExpression
	// regex, if the name starts with a curly bracket it can only be a path variable, and the regex enforces that in
	// such cases the last character will be a right side curly bracket. No additional checks are required.
	if firstCharacter == '{' {
		return name[1 : len(name)-1], PATH_VARIABLE
	}

	// The validPathExpression regex also enforces that if a wildcard is present as a path element, it will always be
	// either one or two wildcards. Based on that, we can confidently check that if the element is the size of a single
	// element then it will be a single wildcard, and otherwise there will surely be two wildcards and it will be a
	// double wildcard type
	if firstCharacter == '*' {
		if len(name) == 1 {
			partType = WILDCARD
		} else {
			partType = DOUBLE_WILDCARD
		}
	}

	return name, partType
}

// Helper function to split the Path variable from the an http.Request in path elements (separated by forward slashes.
// The validPathExpression regex will enforce paths with no empty path elements (double forward slashes). The simple
// splitting process results in similar paths, with identical path elements and differing only in one having a final
// forward slash while the other does not, to be considered identical.
func splitPath(path string) []string {
	// We ignore the first element which will always be empty (behind the forward slash)
	parts := strings.Split(path, "/")[1:]
	// if the endpoint ends with "/" let's ignore the last part too
	lastIndex := len(parts) - 1
	if len(parts[lastIndex]) == 0 {
		parts = parts[:lastIndex]
	}
	return parts
}

// PathTree method that given a path will search the tree depth first for the most specific match, if present, and
// extract the values of any path variables if the matched path expression has path variables. Returns the handler
// for the path as well as a map of variables having the variable names as keys and the corresponding path elements
// as values
func (tree *pathTree) getHandlerAndPathVariables(path string) (interface{}, map[string]string) {
	variables := make(map[string]string)
	parts := splitPath(path)

	if node := matchPathAndVariables(tree.root, parts, variables); node != nil {
		return node.handler, variables
	}

	return nil, variables
}

// Recursive function that will drill down the tree branches and tries to find the longest matching path for the given
// array of path elements. To ensure it takes the most specific match, for each node it will first drill down the
// plain tree node children, then for variable node children, then drills down the wildcard child and finally through
// the double wildcard child. The first full match will be considered the matching path. The child drill down order
// effectively results in first matching for exact path matches, then for paths containing path variables, then with
// wildcards and finally with double wildcards.
func matchPathAndVariables(node *treePathNode, parts []string, variables map[string]string) *treePathNode {

	// there are no more parts in the path, we return the current node if it has a handler
	if len(parts) == 0 {
		if node.handler != nil {
			return node
		}
		// if there is no handler for the node, since there are no more element paths, the search down this
		// branch ends without a match
		return nil
	}

	// for each child, we check if there is an exact match
	// log.Println(parts[0])
	var currentMatch *treePathNode
	remainingParts := parts[1:]
	for _, child := range node.children {
		if parts[0] == child.value {
			// we found an exact match, let's drill down the path
			if foundMatch := matchPathAndVariables(child, remainingParts, variables); foundMatch != nil {
				// there was a match down this path, so we use it
				return foundMatch
			}
		}
		// if it's a path variable we drill down the path, but take preference for an exact match
		if child.pathVariable && currentMatch == nil {
			// it's a variable so let's add the part as a value
			variables[child.value] = parts[0]
			currentMatch = matchPathAndVariables(child, parts[1:], variables)
		}
		// only if there is currently no current match will we drill down the wildcards
	}

	// no matches were found under absolute values, let's check through the variable branches
	for _, variable := range node.variables {
		if foundMatch := matchPathAndVariables(variable, remainingParts, variables); foundMatch != nil {
			// there was a match down this path, so we add the current part value as a variable and return it
			variables[variable.value] = parts[0]
			return foundMatch
		}
	}

	// no matches for variable paths, use the wildcard if it exists
	if node.wildCard != nil {
		if foundMatch := matchPathAndVariables(node.wildCard, remainingParts, variables); foundMatch != nil {
			// there was a match down this path, so we add the current part value as a variable and return it
			return foundMatch
		}
	}

	// finally, we try the double wildcard if present
	if node.doubleWildcard != nil {

		// if the double wildcard has no children, then we return the node
		// if !node.doubleWildcard.hasChildren {
		// 	return node.doubleWildcard
		// }

		// TODO if it has children we need to match the suffixed children. Use wildcard handler for now
		remainingParts = remainingParts[len(remainingParts):]
		return matchPathAndVariables(node.doubleWildcard, remainingParts, variables)
	}

	// nothing was found return nothing
	return nil
}

func (tree *pathTree) addHandler(path string, handler interface{}) (bool, error) {
	if !validPathExpression.MatchString(path) {
		fmt.Println("invalid path added", path)
		return false, errors.New("invalid Path")
	}

	parts := splitPath(path)

	// let's get the closest matchng endpoint
	insertionPoint, index, found := matchSignature(tree.root, parts, 0)
	if found {
		// found a conflicting signature, error and do nothing
		return false, errors.New("path conflict with existing path handler")
	}

	// we now insert one leaf of the matching tree for each part which was not already found in the tree
	for _, part := range parts[index:] {
		name, partType := stripPart(part)
		child := newTreeNode(name)
		switch partType {
		case VALUE:
			insertionPoint.children = append(insertionPoint.children, child)
		case PATH_VARIABLE:
			child.pathVariable = true
			insertionPoint.variables = append(insertionPoint.variables, child)
		case WILDCARD:
			insertionPoint.wildCard = child
		case DOUBLE_WILDCARD:
			insertionPoint.doubleWildcard = child
		}
		insertionPoint = child
	}

	// And finally add the handler at the tip of the branch
	insertionPoint.handler = handler

	return true, nil
}

// Lists all the routes registered in the path tree
func (tree *pathTree) ListRoutes() []string {
	// let's build the list of registered endpoints from the root
	return getRoutes("", tree.root)
}

// Recursive function that will drill down depth-first tree branches and return the registered endpoint paths from
// the current branch. The function is called with the full sub-path of all the parent nodes, which act as prefix for
// all sub-paths found in the current node
func getRoutes(prefix string, node *treePathNode) []string {
	var listOfRoutes []string

	// path variable nodes are identified by the flag and returned with curly brackets to make them identifiable
	// the node value is added to the prefix being the full path to reach the current node, and the prefix for all
	// child node paths
	if node.pathVariable {
		prefix = prefix + "/{" + node.value + "}"
	} else {
		prefix = prefix + "/" + node.value
	}

	// If the current node has a handler then it matches an endpoint. We add it to the list of all sub-path endpoints
	// starting at the current node
	if node.handler != nil {
		listOfRoutes = []string{prefix}
	}

	// All the children nodes of the current node will be drilled down to find their matching sub-paths
	for _, child := range node.children {
		listOfRoutes = append(listOfRoutes, getRoutes(prefix, child)...)
	}
	for _, variable := range node.variables {
		listOfRoutes = append(listOfRoutes, getRoutes(prefix, variable)...)
	}
	if node.wildCard != nil {
		listOfRoutes = append(listOfRoutes, getRoutes(prefix, node.wildCard)...)
	}
	if node.doubleWildcard != nil {
		listOfRoutes = append(listOfRoutes, getRoutes(prefix, node.doubleWildcard)...)
	}

	// Returns all the paths found down this node.
	return listOfRoutes
}

// recursive function to check a match for a path signature through any of the branches
func matchSignature(node *treePathNode, parts []string, depth int) (*treePathNode, int, bool) {
	// if there are no more parts, we return the current node, and consider it found if the node has a handler
	if len(parts) == 0 {
		// log.Println("signature not found")
		return node, depth, node.handler != nil
	}

	// if there are parts, let's match it with the the possible types in existence
	name, partType := stripPart(parts[0])
	var children *[]*treePathNode
	if partType == VALUE {
		children = &node.children
		partType = PATH_PART
	} else if partType == PATH_VARIABLE {
		children = &node.variables
		partType = PATH_PART
	}

	switch partType {
	case PATH_PART:
		// needs an exact match
		for _, child := range *children {
			if child.value == name {
				return matchSignature(child, parts[1:], depth+1) // found a match, let's dig through it
			}
		}
	case WILDCARD:
		// it's a wildcard, if there is no wildcard, return the node as insertion point, if there is, match through the branch
		if node.wildCard != nil {
			return matchSignature(node.wildCard, parts[1:], depth+1)
		}
	case DOUBLE_WILDCARD:
		// as in wildcard, match the branch if there is one, or it's not found and the current node is the insertion point
		if node.doubleWildcard != nil {
			return matchSignature(node.doubleWildcard, parts[1:], depth+1)
		}
	}

	// there were no matches or partial matches. Current node is the insertion point
	return node, depth, false
}
