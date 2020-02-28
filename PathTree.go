// Copyright 2020 GOM. All rights reserved.
// Since 27/02/2020 By GOM
// Licensed under MIT License

package we

import (
	"log"
	"regexp"
	"strings"
)

const (
	VALUE           = iota
	PATH_VARIABLE
	WILDCARD
	DOUBLE_WILDCARD
)

var (
	validPathExpression = regexp.MustCompile("^(/|(/(([a-zA-Z0-9_\\-@~]|%[0-9a-fA-f]{2})+|{[a-zA-Z0-9]+}|\\*\\*?))*/?)$")
)

type treePathNode struct {
	value           string
	pathVariable    bool
	hasChildren     bool
	wildCard       *treePathNode
	doubleWildcard *treePathNode
	handler         interface{}
	children     []*treePathNode
	variables    []*treePathNode
}

type pathTree struct {
	root *treePathNode
}

func newTreeNode(name string) *treePathNode {
	result := new(treePathNode)
	result.value = name
	result.children  = make([]*treePathNode,0)
	result.variables = make([]*treePathNode,0)
	return result
}

func newPathTree() *pathTree {
	result := new(pathTree);
	result.root = newTreeNode("root")
	return result
}

func stripPart(name string) (string, int) {
	firstCharacter := name[0]
	partType := VALUE
	if firstCharacter == '{' {
		return name[1:len(name)-1], PATH_VARIABLE
	}

	if firstCharacter == '*' {
		if len(name) == 1 {
			partType = WILDCARD
		} else {
			partType = DOUBLE_WILDCARD
		}
	}

	return name, partType
}

func splitPath(path string) []string {
	// We ignore the first element which will always be empty (behind the forward slash)
	parts := strings.Split(path, "/")[1:]
	// if the endpoint ends with "/" let's ignore the last part too
	lastIndex := len(parts)-1
	if len(parts[lastIndex]) == 0 {
		parts = parts[:lastIndex]
	}
	return parts
}

//func (tree *pathTree) getHandlerAndPathVariables(path string) (func(w http.ResponseWriter, context *RequestContext), map[string]string) {
func (tree *pathTree) getHandlerAndPathVariables(path string) (interface{}, map[string]string) {
	variables := make(map[string]string)
	parts := splitPath(path)

	if node := matchPathAndVariables(tree.root, parts, variables); node != nil {
		return node.handler, variables
	}

	return nil,variables
}

// This is a recursive function, it will drill down the tree branches taking preference for the longest possible match
func matchPathAndVariables(node *treePathNode, parts []string, variables map[string]string) *treePathNode {
	// there are no more parts in the path, we return the current node if it has a handler
	if len(parts) == 0 {
		if node.handler != nil {
			return node
		}
		return nil
	}

	// for each child, we check if there is an exact match
	log.Println(parts[0])
	var currentMatch *treePathNode
	remainingParts := parts[1:]
	for _, child := range node.children {
		if parts[0] == child.value  {
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
		// if the double wildcard branch also has a single or double wildcard, then we drill down the branch, if not we keep it where it is
		nextNode := node
		if node.doubleWildcard.wildCard != nil || node.doubleWildcard.doubleWildcard != nil {
			nextNode = node.doubleWildcard
		}
		if foundMatch := matchPathAndVariables(nextNode, remainingParts, variables); foundMatch != nil {
			// there was a match down this path, so we add the current part value as a variable and return it
			return foundMatch
		}
	}

	// nothing was found return nothing
	return nil
}

func (tree *pathTree) addHandler(path string, handler interface{}) (bool, error) {
	if !validPathExpression.MatchString(path) {
		return false, newWebEngineError("Invalid Path")
	}

	parts := splitPath(path)

	// let's get the closest matching endpoint
	insertionPoint, index, found := matchSignature(tree.root,parts,0)
	if found {
		// found a conflicting signature, error and do nothing
		return false, newWebEngineError("Path conflict with existing path handler")
	}

	// we now insert one leaf of the matching tree for each part which was not already found in the tree
	for _, part := range parts[index:] {
		name, partType := stripPart(part)
		child := newTreeNode(name)
		switch partType {
		case VALUE :
			insertionPoint.children = append(insertionPoint.children,child)
		case PATH_VARIABLE :
			child.pathVariable = true
			insertionPoint.variables = append(insertionPoint.variables,child)
		case WILDCARD :
			insertionPoint.wildCard = child
		case DOUBLE_WILDCARD :
			insertionPoint.doubleWildcard = child
		}
		insertionPoint = child
	}

	// And finally add the handler at the tip of the branch
	insertionPoint.handler = handler

	return true, nil
}

func (tree *pathTree) ListRoutes() []string {
	// let's build the list of registered endpoints from the root
	return getRoutes("",tree.root)
}

func getRoutes(prefix string, node *treePathNode) []string {
	var listOfRoutes []string
	if node.pathVariable {
		prefix = prefix + "/{" + node.value + "}"
	} else {
		prefix = prefix + "/" + node.value
	}
	if node.handler != nil {
		listOfRoutes = []string{prefix}
	}
	for _, child := range node.children {
		listOfRoutes = append(listOfRoutes, getRoutes( prefix, child)...)
	}
	for _, variable := range node.variables {
		listOfRoutes = append(listOfRoutes, getRoutes( prefix, variable)...)
	}
	if node.wildCard != nil {
		listOfRoutes = append(listOfRoutes, getRoutes( prefix, node.wildCard)...)
	}
	if node.doubleWildcard != nil {
		listOfRoutes = append(listOfRoutes, getRoutes( prefix, node.doubleWildcard)...)
	}
    return listOfRoutes
}

// recursive function to check the match of a path signature through any of the branches
func matchSignature(node *treePathNode, parts []string, depth int) (*treePathNode, int, bool) {
	// if there are no more parts, we return the current node, and consider it found if the node has a handler
	if len(parts) == 0 {
		log.Println("signature not found")
		return node, depth, node.handler != nil
	}

	// if there are parts, let's match it with the the possible types in existence
	name, partType := stripPart(parts[0])

	switch partType {
	case VALUE:
		// needs an exact match
		for _, child := range node.children {
			if child.value == name {
				return matchSignature(child, parts[1:], depth + 1)// found a match, let's dig through it
			}
		}
	case PATH_VARIABLE:
		// for path variables we check all the variables at this level, if we find a signature match, we return it, if
		// not we either return the current node as an insertion point if there is no namesake variable, or we return
		// the namesake variable match path
		insertionPoint := node
		insertionDepth := depth
		for _, variable := range node.variables {
			// first we check if a signature is matched for any variable we find
			foundNode, foundDepth, found := matchSignature(variable, parts[1:], depth + 1)
			if variable.value == name {
				// we found a namesake variable, the insertion point will be the one returned from the match
				insertionPoint = foundNode
				depth = foundDepth
			}
			if found {
				return foundNode, foundDepth, found
			}
		}
		// if we went through all variables at this level and found no match, we return the insertion point and depth
		return insertionPoint, insertionDepth, false
	case WILDCARD:
		// it's a wildcard, if there is no wildcard, return the node as insertion point, if there is, match through the branch
		if node.wildCard != nil {
			return matchSignature(node.wildCard, parts[1:], depth + 1)
		}
	case DOUBLE_WILDCARD:
		// as in wildcard, match the branch if there is one, or it's not found and the current node is the insertion point
		if node.doubleWildcard != nil {
			return matchSignature(node.doubleWildcard, parts[1:], depth + 1)
		}
	}

	// there were no matches or partial matches. Current node is the insertion point
	return node, depth, false
}
