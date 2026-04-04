# Contributing to go-we

Thank you for your interest in contributing to go-we! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Design Discussions](#design-discussions)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, background, or identity.

### Our Standards

**Expected behavior:**
- Be respectful and considerate in communication
- Focus on what is best for the project and community
- Accept constructive criticism gracefully
- Show empathy towards other community members

**Unacceptable behavior:**
- Harassment, discrimination, or offensive comments
- Personal attacks or insults
- Publishing others' private information without permission
- Other conduct that would be inappropriate in a professional setting

### Enforcement

Instances of unacceptable behavior may be reported to the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check the [existing issues](https://github.com/gomatbase/go-we/issues) to avoid duplicates
2. Ensure you're using the latest version
3. Verify the issue is reproducible

When submitting a bug report, include:
- **Clear title** - Descriptive summary of the issue
- **Description** - Detailed explanation of the problem
- **Steps to reproduce** - Minimal code example demonstrating the issue
- **Expected behavior** - What you expected to happen
- **Actual behavior** - What actually happened
- **Environment** - Go version, OS, go-we version
- **Additional context** - Stack traces, logs, screenshots if applicable

**Example:**

```markdown
## Bug: Session not refreshing with rolling timeout

**Description**: When using rolling sessions, the LastUse timestamp doesn't update.

**Steps to reproduce**:
```go
config := we.SessionManagerConfiguration{
    SessionTimeout: 30 * time.Minute,
    StaticSessionLifespan: false,
}
engine.SetSessionManager(we.DefaultSessionManager(config))
// Make requests within 30 minutes, session still expires
```

**Expected**: Session should extend by 30 minutes on each request
**Actual**: Session expires after initial 30 minutes regardless of activity

**Environment**: Go 1.24.0, go-we v0.9.0, macOS 14.0
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When suggesting an enhancement:

- **Use a clear title** describing the enhancement
- **Provide detailed description** of the proposed functionality
- **Explain the motivation** - Why is this useful?
- **Describe alternatives** - What other approaches did you consider?
- **Show examples** - How would the API look?
- **Consider backward compatibility** - Will this break existing code?

### Contributing Code

We welcome code contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Ensure all tests pass** (`go test ./...`)
6. **Commit your changes** with clear messages
7. **Push to your fork** (`git push origin feature/amazing-feature`)
8. **Open a Pull Request**

## Development Setup

### Prerequisites

- Go 1.24.0 or higher
- Git

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/go-we.git
cd go-we

# Add upstream remote
git remote add upstream https://github.com/gomatbase/go-we.git

# Install dependencies (none external - only standard library)
go mod download

# Run tests to verify setup
go test ./...
```

### Project Structure

```
go-we/
├── engine.go              # Core engine implementation
├── session.go             # Session management
├── error.go               # Error handling
├── events/                # Event system
│   └── error.go
├── security/              # Authentication and authorization
│   ├── Filter.go
│   ├── Authorization.go
│   ├── Authentication*.go
│   └── doc.go
├── filters/               # Built-in filters
│   ├── cors.go
│   ├── response_headers.go
│   └── doc.go
├── pathTree/              # Path matching
│   ├── PathTree.go
│   └── PathTree_test.go
├── util/                  # Utility functions
│   ├── request.go
│   ├── response.go
│   └── doc.go
├── test/                  # Testing utilities
│   └── RequestScopeMocker.go
└── docs/                  # Documentation
    ├── ARCHITECTURE.md
    ├── BEST_PRACTICES.md
    └── API_DESIGN.md
```

## Coding Standards

### Go Style Guide

We follow standard Go conventions:
- [Effective Go](https://golang.org/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

### Specific Guidelines

**Naming:**
- Use `MixedCaps` or `mixedCaps` (no underscores)
- Exported identifiers start with uppercase
- Short, clear names for local variables (`i`, `err`, `req`)
- Descriptive names for exported APIs

**Documentation:**
- All exported types, functions, and methods must have godoc comments
- Comments should be complete sentences starting with the name
- Include examples for complex APIs

```go
// Good
// DefaultSessionManager creates a SessionManager with the provided configuration.
// The session manager handles session lifecycle, storage, and cookie management.
func DefaultSessionManager(config SessionManagerConfiguration) SessionManager {
    // ...
}

// Bad
// creates session manager
func DefaultSessionManager(config SessionManagerConfiguration) SessionManager {
    // ...
}
```

**Error Handling:**
- Return errors, don't panic (unless truly unrecoverable)
- Wrap errors with context using `fmt.Errorf` with `%w`
- Use `WeEvent` types for HTTP errors

**Testing:**
- Test files named `*_test.go`
- Test functions named `TestXxx`
- Use table-driven tests for multiple cases
- Aim for high code coverage of critical paths

### Code Formatting

```bash
# Format code
go fmt ./...

# Run linter (if using golangci-lint)
golangci-lint run

# Vet code
go vet ./...
```

## Testing Guidelines

### Writing Tests

**Unit Tests:**
```go
func TestUserHandler(t *testing.T) {
    tests := []struct {
        name       string
        userID     string
        wantStatus int
        wantError  error
    }{
        {
            name:       "valid user",
            userID:     "123",
            wantStatus: 200,
            wantError:  nil,
        },
        {
            name:       "user not found",
            userID:     "999",
            wantStatus: 404,
            wantError:  events.NotFoundError,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mocker := test.RequestScopeMocker{
                Variables: map[string]string{"id": tt.userID},
            }
            scope := mocker.Mock()
            w := httptest.NewRecorder()

            err := getUserHandler(w, scope)

            if !errors.Is(err, tt.wantError) {
                t.Errorf("got error %v, want %v", err, tt.wantError)
            }
        })
    }
}
```

**Integration Tests:**
```go
func TestAPIIntegration(t *testing.T) {
    engine := we.New()
    engine.Handle("/api/users/{id}", getUserHandler)
    
    server := httptest.NewServer(engine.Handler())
    defer server.Close()
    
    resp, err := http.Get(server.URL + "/api/users/123")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        t.Errorf("got status %d, want 200", resp.StatusCode)
    }
}
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run with race detector
go test -race ./...

# Run specific test
go test -run TestUserHandler ./...

# Verbose output
go test -v ./...
```

### Test Coverage

- Aim for >80% coverage on critical paths
- 100% coverage not required but appreciated
- Focus on edge cases and error paths
- Mock external dependencies

## Pull Request Process

### Before Submitting

1. **Update documentation** - If you change APIs, update godoc and relevant docs
2. **Add tests** - Ensure new code has test coverage
3. **Run tests** - `go test ./...` must pass
4. **Format code** - Run `go fmt ./...`
5. **Commit messages** - Use clear, descriptive commit messages

### PR Description Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- List of changes made
- Another change

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] All tests pass
- [ ] Code formatted with `go fmt`
```

### Review Process

1. **Buildable** - Project remains buildable and tests fully run
2. **Maintainer review** - Maintainer must approve
3. **Address feedback** - Respond to review comments
4. **Approval** - Once approved, maintainer will merge

### After Merge

- Your contribution will be included in the next release
- You'll be credited in release notes
- Thank you for contributing!

## Design Discussions

For significant changes that affect the API or architecture:

### Starting a Design Discussion

1. **Open an issue** with `[Design]` prefix
2. **Explain the problem** - What pain point are you solving?
3. **Propose solution** - How would it work?
4. **Show examples** - Code examples of the proposed API
5. **Discuss alternatives** - What other approaches exist?
6. **Consider trade-offs** - What are the downsides?

### Design Principles to Consider

From [API_DESIGN.md](docs/API_DESIGN.md):

1. **Standard Library First** - Build on `net/http`, don't replace it
2. **Minimal Dependencies** - Avoid external dependencies when possible
3. **Type Safety** - Leverage Go's type system
4. **Explicit Over Implicit** - No magic or hidden behavior
5. **Flexibility** - Provide interfaces for customization

### API Stability

- **Breaking changes** require major version bump
- **Backward compatibility** is a priority
- **Deprecation** requires at least one minor version warning

## Questions?

- **Documentation**: See [docs/](docs/) directory
- **Issues**: [GitHub Issues](https://github.com/gomatbase/go-we/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gomatbase/go-we/discussions)

Thank you for contributing to go-we! 🎉
