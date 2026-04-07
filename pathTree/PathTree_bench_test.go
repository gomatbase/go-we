// Copyright 2026 GOM. All rights reserved.
// Since 07/04/2026 By GOM
// Licensed under MIT License

package pathTree_test

import (
	"testing"

	"github.com/gomatbase/go-we/pathTree"
)

// BenchmarkPathTreeAddStatic benchmarks adding static paths
func BenchmarkPathTreeAddStatic(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tree := pathTree.New[string]()
		_ = tree.Add("/api/users", "handler1")
		_ = tree.Add("/api/posts", "handler2")
		_ = tree.Add("/api/comments", "handler3")
	}
}

// BenchmarkPathTreeAddWithVariables benchmarks adding paths with variables
func BenchmarkPathTreeAddWithVariables(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tree := pathTree.New[string]()
		_ = tree.Add("/users/{id}", "handler1")
		_ = tree.Add("/users/{id}/posts/{postId}", "handler2")
		_ = tree.Add("/api/{version}/resource/{id}", "handler3")
	}
}

// BenchmarkPathTreeAddWithWildcards benchmarks adding paths with wildcards
func BenchmarkPathTreeAddWithWildcards(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tree := pathTree.New[string]()
		_ = tree.Add("/api/*", "handler1")
		_ = tree.Add("/api/**", "handler2")
		_ = tree.Add("/files/*", "handler3")
	}
}

// BenchmarkPathTreeGetStatic benchmarks getting static paths
func BenchmarkPathTreeGetStatic(b *testing.B) {
	tree := pathTree.New[string]()
	_ = tree.Add("/api/users", "handler1")
	_ = tree.Add("/api/posts", "handler2")
	_ = tree.Add("/api/comments", "handler3")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/api/users")
	}
}

// BenchmarkPathTreeGetWithVariable benchmarks getting paths with variables
func BenchmarkPathTreeGetWithVariable(b *testing.B) {
	tree := pathTree.New[string]()
	_ = tree.Add("/users/{id}", "handler1")
	_ = tree.Add("/users/{id}/posts/{postId}", "handler2")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/users/12345")
	}
}

// BenchmarkPathTreeGetWithMultipleVariables benchmarks getting paths with multiple variables
func BenchmarkPathTreeGetWithMultipleVariables(b *testing.B) {
	tree := pathTree.New[string]()
	_ = tree.Add("/users/{id}/posts/{postId}/comments/{commentId}", "handler")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/users/123/posts/456/comments/789")
	}
}

// BenchmarkPathTreeGetWithWildcard benchmarks getting paths with wildcards
func BenchmarkPathTreeGetWithWildcard(b *testing.B) {
	tree := pathTree.New[string]()
	_ = tree.Add("/api/**", "handler")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/api/v1/users/123/posts")
	}
}

// BenchmarkPathTreeGetMiss benchmarks getting a non-existent path
func BenchmarkPathTreeGetMiss(b *testing.B) {
	tree := pathTree.New[string]()
	_ = tree.Add("/api/users", "handler1")
	_ = tree.Add("/api/posts", "handler2")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/api/notfound")
	}
}

// BenchmarkPathTreeComplexRouting benchmarks complex routing scenario
func BenchmarkPathTreeComplexRouting(b *testing.B) {
	tree := pathTree.New[string]()

	// Add various types of routes
	_ = tree.Add("/", "home")
	_ = tree.Add("/api/v1/users", "listUsers")
	_ = tree.Add("/api/v1/users/{id}", "getUser")
	_ = tree.Add("/api/v1/users/{id}/posts", "getUserPosts")
	_ = tree.Add("/api/v1/users/{id}/posts/{postId}", "getPost")
	_ = tree.Add("/api/v1/posts", "listPosts")
	_ = tree.Add("/api/v1/posts/{id}", "getPost")
	_ = tree.Add("/api/v2/**", "v2Handler")
	_ = tree.Add("/files/*", "fileHandler")
	_ = tree.Add("/static/**", "staticHandler")

	paths := []string{
		"/api/v1/users",
		"/api/v1/users/12345",
		"/api/v1/users/12345/posts",
		"/api/v1/users/12345/posts/67890",
		"/api/v2/some/nested/path",
		"/files/document.pdf",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		path := paths[i%len(paths)]
		_, _ = tree.Get(path)
	}
}

// BenchmarkPathTreeManyRoutes benchmarks with many registered routes
func BenchmarkPathTreeManyRoutes(b *testing.B) {
	tree := pathTree.New[string]()

	// Register 100 routes
	for i := 0; i < 100; i++ {
		path := "/api/endpoint" + string(rune('0'+i%10)) + string(rune('0'+i/10))
		_ = tree.Add(path, "handler")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/api/endpoint50")
	}
}

// BenchmarkPathTreePrecedence benchmarks path precedence resolution
func BenchmarkPathTreePrecedence(b *testing.B) {
	tree := pathTree.New[string]()

	// Add routes in order of precedence
	_ = tree.Add("/api/users/me", "exactMatch")     // Most specific
	_ = tree.Add("/api/users/{id}", "withVariable") // Less specific
	_ = tree.Add("/api/**", "catchAll")             // Least specific

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/api/users/me")
	}
}

// BenchmarkPathTreeDeepNesting benchmarks deeply nested paths
func BenchmarkPathTreeDeepNesting(b *testing.B) {
	tree := pathTree.New[string]()
	_ = tree.Add("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", "deepHandler")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tree.Get("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p")
	}
}
