# Go-We Examples

This directory contains practical examples demonstrating the features and capabilities of the go-we web framework.

## Getting Started

Each example is self-contained with its own `main.go` and `README.md`. Navigate to any example directory and run:

```bash
go run main.go
```

## Examples by Category

### Basic Concepts

1. **[01-basic-routing](01-basic-routing/)** - Simple HTTP routing with GET/POST handlers
2. **[02-path-variables](02-path-variables/)** - Path variables, wildcards, and URL parameters
3. **[09-error-handling](09-error-handling/)** - Custom error handlers and error responses

### Session & State Management

3. **[03-session-management](03-session-management/)** - Session creation, storage, and configuration
4. **[04-custom-filters](04-custom-filters/)** - Creating and applying custom filters

### Authentication

5. **[05-basic-auth](05-basic-auth/)** - HTTP Basic Authentication
6. **[06-bearer-token](06-bearer-token/)** - Bearer token authentication with JWT
7. **[07-form-login](07-form-login/)** - Form-based login authentication

### Authorization

10. **[08-authorization](08-authorization/)** - Role-based access control (RBAC)

### API Development

12. **[10-rest-api](10-rest-api/)** - RESTful API with JSON request/response
13. **[11-static-files](11-static-files/)** - Serving static files and assets

### Complete Applications

14. **[12-full-application](12-full-application/)** - Complete application with authentication, authorization, and session management

## Running Examples

All examples can be run independently:

```bash
cd examples/01-basic-routing
go run main.go
```

Then visit `http://localhost:8080` in your browser or use curl:

```bash
curl http://localhost:8080
```

## Example Structure

Each example follows this structure:

```
XX-example-name/
├── main.go       # Runnable example code
└── README.md     # Detailed explanation and usage
```

## Learning Path

We recommend following the examples in order:

1. Start with **01-basic-routing** to understand routing basics
2. Move to **02-path-variables** for dynamic routing
3. Learn **03-session-management** for stateful applications
4. Explore authentication examples (05-07) based on your needs
5. Study **08-authorization** for access control
6. Review **10-rest-api** for API development
7. Examine **12-full-application** to see everything together

## Additional Resources

- [Main README](../README.md) - Framework overview
- [Architecture Guide](../docs/ARCHITECTURE.md) - System architecture
- [Best Practices](../docs/BEST_PRACTICES.md) - Security and performance guidelines
- [API Design](../docs/API_DESIGN.md) - Design philosophy
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute

## Questions?

If you have questions or need help:

1. Check the example's README.md for specific guidance
2. Review the [Best Practices](../docs/BEST_PRACTICES.md) guide
3. Open an issue on GitHub

Enjoy building with go-we! 🚀
