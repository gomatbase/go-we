# Logging Guide

The go-we framework provides a structured logging interface for consistent logging across the entire application. This guide explains how to set up and customize logging in your application.

## Table of Contents

1. [Overview](#overview)
2. [Default Logger](#default-logger)
3. [Configuring Logger](#configuring-logger)
4. [Custom Logger Implementation](#custom-logger-implementation)
5. [Best Practices](#best-practices)
6. [Examples](#examples)

## Overview

The framework uses a simple but extensible `Logger` interface that provides five logging methods:

- `Debug(msg string)` - Log debug-level messages
- `Info(msg string)` - Log informational messages
- `Warn(msg string)` - Log warning messages
- `Error(msg string)` - Log error messages
- `Log(level int, msg string)` - Log with explicit level

Log level constants are available:
- `we.LogLevelDebug`
- `we.LogLevelInfo`
- `we.LogLevelWarn`
- `we.LogLevelError`

By default, all framework components (engine, session manager, security filter, error handler) initialize with the `DefaultLogger` which prints messages to stdout with log level prefixes.

## Default Logger

The default logger prints to stdout with the following format:

```
[INFO] Server started
[WARN] Session timeout approaching
[ERROR] Failed to authenticate user
[DEBUG] Request received from 192.168.1.1
```

### Using Default Logger

No configuration is required to use the default logger:

```go
package main

import (
    "time"
    we "github.com/gomatbase/go-we"
    "github.com/gomatbase/go-we/security"
)

func main() {
    // Engine will use DefaultLogger automatically
    engine := we.New().
        ReadHeaderTimeout(15 * time.Second).
        Build()

    engine.Handle("/", handler)
    engine.Listen(":8080")  // Output: [INFO] Listening on :8080
}

func handler(w http.ResponseWriter, scope we.RequestScope) error {
    return util.ReplyJson(w, http.StatusOK, map[string]string{"status": "ok"})
}
```

## Configuring Logger

You can configure custom loggers at three levels:

### 1. Engine Logger

Configure logging for the entire engine and core operations:

```go
customLogger := MyCustomLogger{}

engine := we.New().
    Logger(customLogger).
    Build()
```

### 2. Session Manager Logger

Configure logging for session management and purging:

```go
customLogger := MyCustomLogger{}

sessionManager := we.DefaultSessionManager().
    SessionTimeout(time.Hour).
    Logger(customLogger).
    Build()

engine := we.New().
    SessionManager(sessionManager).
    Build()
```

### 3. Security Filter Logger

Configure logging for authentication and authorization:

```go
customLogger := MyCustomLogger{}

filter := security.DefaultSecurityFilter().
    Authentication(provider).
    Logger(customLogger).
    Build()

engine := we.New().
    Filter(filter).
    Build()
```

## Custom Logger Implementation

Implement the `Logger` interface to integrate your logging framework:

### Example: File Logger

```go
package logging

import (
    "fmt"
    "log"
    "os"
    we "github.com/gomatbase/go-we"
)

type FileLogger struct {
    file *os.File
}

func NewFileLogger(filepath string) (*FileLogger, error) {
    file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return nil, err
    }
    return &FileLogger{file: file}, nil
}

func (fl *FileLogger) Debug(msg string) {
    fl.log("[DEBUG]", msg)
}

func (fl *FileLogger) Info(msg string) {
    fl.log("[INFO]", msg)
}

func (fl *FileLogger) Warn(msg string) {
    fl.log("[WARN]", msg)
}

func (fl *FileLogger) Error(msg string) {
    fl.log("[ERROR]", msg)
}

func (fl *FileLogger) Log(level int, msg string) {
    switch level {
    case we.LogLevelDebug:
        fl.Debug(msg)
    case we.LogLevelInfo:
        fl.Info(msg)
    case we.LogLevelWarn:
        fl.Warn(msg)
    case we.LogLevelError:
        fl.Error(msg)
    default:
        fl.log("[UNKNOWN]", msg)
    }
}

func (fl *FileLogger) log(level, msg string) {
    entry := fmt.Sprintf("%s %s\n", level, msg)
    if _, err := fl.file.WriteString(entry); err != nil {
        log.Printf("Failed to write log: %v\n", err)
    }
}

func (fl *FileLogger) Close() error {
    return fl.file.Close()
}
```

Usage:

```go
func main() {
    logger, err := logging.NewFileLogger("app.log")
    if err != nil {
        log.Fatal(err)
    }
    defer logger.Close()

    engine := we.New().
        Logger(logger).
        Build()

    engine.Listen(":8080")  // Logs to app.log instead of stdout
}
```

### Example: Structured JSON Logger

```go
package logging

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    we "github.com/gomatbase/go-we"
)

type JSONLogger struct {
    logger *log.Logger
}

func NewJSONLogger() *JSONLogger {
    return &JSONLogger{
        logger: log.New(os.Stdout, "", 0),
    }
}

type LogEntry struct {
    Level     string `json:"level"`
    Message   string `json:"message"`
    Timestamp string `json:"timestamp"`
}

func (jl *JSONLogger) Debug(msg string) {
    jl.logJSON("DEBUG", msg)
}

func (jl *JSONLogger) Info(msg string) {
    jl.logJSON("INFO", msg)
}

func (jl *JSONLogger) Warn(msg string) {
    jl.logJSON("WARN", msg)
}

func (jl *JSONLogger) Error(msg string) {
    jl.logJSON("ERROR", msg)
}

func (jl *JSONLogger) Log(level int, msg string) {
    levelStr := "UNKNOWN"
    switch level {
    case we.LogLevelDebug:
        levelStr = "DEBUG"
    case we.LogLevelInfo:
        levelStr = "INFO"
    case we.LogLevelWarn:
        levelStr = "WARN"
    case we.LogLevelError:
        levelStr = "ERROR"
    }
    jl.logJSON(levelStr, msg)
}

func (jl *JSONLogger) logJSON(level, msg string) {
    entry := LogEntry{
        Level:     level,
        Message:   msg,
        Timestamp: time.Now().RFC3339,
    }
    data, _ := json.Marshal(entry)
    jl.logger.Println(string(data))
}
```

Usage:

```go
engine := we.New().
    Logger(logging.NewJSONLogger()).
    Build()
```

### Example: Conditional Logger

```go
package logging

import (
    "fmt"
    we "github.com/gomatbase/go-we"
)

type ConditionalLogger struct {
    minLevel int
}

func NewConditionalLogger(minLevel int) *ConditionalLogger {
    return &ConditionalLogger{minLevel: minLevel}
}

func (cl *ConditionalLogger) Debug(msg string) {
    if cl.minLevel <= we.LogLevelDebug {
        fmt.Println("[DEBUG]", msg)
    }
}

func (cl *ConditionalLogger) Info(msg string) {
    if cl.minLevel <= we.LogLevelInfo {
        fmt.Println("[INFO]", msg)
    }
}

func (cl *ConditionalLogger) Warn(msg string) {
    if cl.minLevel <= we.LogLevelWarn {
        fmt.Println("[WARN]", msg)
    }
}

func (cl *ConditionalLogger) Error(msg string) {
    if cl.minLevel <= we.LogLevelError {
        fmt.Println("[ERROR]", msg)
    }
}

func (cl *ConditionalLogger) Log(level int, msg string) {
    if level >= cl.minLevel {
        fmt.Printf("[%d] %s\n", level, msg)
    }
}
```

Usage:

```go
// Only log warnings and errors in production
engine := we.New().
    Logger(logging.NewConditionalLogger(we.LogLevelWarn)).
    Build()
```

## Best Practices

### 1. Configure All Components Consistently

When using a custom logger, configure it for all components for consistent logging:

```go
customLogger := MyCustomLogger{}

sessionManager := we.DefaultSessionManager().
    Logger(customLogger).
    Build()

filter := security.DefaultSecurityFilter().
    Authentication(provider).
    Logger(customLogger).
    Build()

engine := we.New().
    Logger(customLogger).
    SessionManager(sessionManager).
    Filter(filter).
    Build()
```

### 2. Handle Logger Initialization Failures

If your logger requires setup (like opening a file), handle errors properly:

```go
logger, err := logging.NewFileLogger("app.log")
if err != nil {
    log.Fatalf("Failed to initialize logger: %v", err)
}
defer logger.Close()

engine := we.New().
    Logger(logger).
    Build()
```

### 3. Use Structured Data When Possible

Implement loggers that can handle context-rich messages:

```go
// Instead of:
logger.Error("Failed to process request")

// Use:
logger.Error(fmt.Sprintf("Failed to process request from %s: %v", clientIP, err))
```

### 4. Development vs. Production

Use different loggers for development and production:

```go
func createLogger(isDev bool) we.Logger {
    if isDev {
        return we.NewDefaultLogger()  // stdout with prefixes
    }
    
    prodLogger, _ := logging.NewFileLogger("production.log")
    return prodLogger
}

engine := we.New().
    Logger(createLogger(os.Getenv("ENV") == "development")).
    Build()
```

## Examples

### Complete Setup with Custom Logger

```go
package main

import (
    "log"
    "time"
    we "github.com/gomatbase/go-we"
    "github.com/gomatbase/go-we/security"
    "github.com/gomatbase/go-we/util"
    "github.com/gomatbase/go-we/docs/logging"
)

func main() {
    // Initialize custom logger
    logger, err := logging.NewFileLogger("app.log")
    if err != nil {
        log.Fatal(err)
    }
    defer logger.Close()

    // Create session manager with logger
    sessionManager := we.DefaultSessionManager().
        SessionTimeout(2 * time.Hour).
        Logger(logger).
        Build()

    // Create security filter with logger
    provider := security.BasicAuthenticationProvider(
        security.User{Username: "admin", Password: "secret"},
    ).Build()

    filter := security.DefaultSecurityFilter().
        Authentication(provider).
        Logger(logger).
        Build()

    // Create engine with all loggers configured
    engine := we.New().
        Logger(logger).
        SessionManager(sessionManager).
        Filter(filter).
        ReadHeaderTimeout(15 * time.Second).
        Build()

    // Register handlers
    engine.Handle("/public", publicHandler)
    engine.HandleMethod("GET", "/secure", secureHandler)

    // Listen (logs to app.log)
    engine.Listen(":8080")
}

func publicHandler(w http.ResponseWriter, scope we.RequestScope) error {
    return util.ReplyJson(w, http.StatusOK, map[string]string{
        "message": "Welcome",
    })
}

func secureHandler(w http.ResponseWriter, scope we.RequestScope) error {
    user := scope.Get(security.UserAttributeName).(*security.User)
    return util.ReplyJson(w, http.StatusOK, map[string]string{
        "user": user.Username,
    })
}
```

### Log Level-Based Filtering

```go
// In production, only log warnings and errors
prodLogger := logging.NewConditionalLogger(we.LogLevelWarn)

// In development, log everything
devLogger := we.NewDefaultLogger()

loggerToUse := prodLogger
if os.Getenv("DEBUG") == "true" {
    loggerToUse = devLogger
}

engine := we.New().
    Logger(loggerToUse).
    Build()
```

## Summary

The go-we logging system is simple, extensible, and integrates throughout the framework:

- ✅ Default logger works out-of-the-box
- ✅ Easy to implement custom loggers
- ✅ Configure logging at engine, session, and filter levels
- ✅ All framework errors and important events are logged
- ✅ Development-friendly with clear, readable output
