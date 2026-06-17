// Copyright 2023-2026 GOM. All rights reserved.
// Since 17/06/2026 By GOM
// Licensed under MIT License

package we

import "fmt"

// Log level constants
const (
	// LogLevelDebug represents debug level logging
	LogLevelDebug int = iota
	// LogLevelInfo represents info level logging
	LogLevelInfo
	// LogLevelWarn represents warning level logging
	LogLevelWarn
	// LogLevelError represents error level logging
	LogLevelError
)

// Logger provides a simple logging interface for the framework.
// Implementations should log to an appropriate destination (stdout, files, etc).
type Logger interface {
	// Debug logs a debug-level message
	Debug(msg string)
	// Info logs an informational message
	Info(msg string)
	// Warn logs a warning message
	Warn(msg string)
	// Error logs an error message
	Error(msg string)
	// Log logs a message with the given level
	Log(level int, msg string)
}

// DefaultLogger provides a logger implementation that prints to stdout.
// It prefixes each message with the log level in brackets (e.g., [DEBUG], [INFO], [WARN], [ERROR]).
type DefaultLogger struct{}

// Debug logs a debug message with [DEBUG] prefix
func (d *DefaultLogger) Debug(msg string) {
	fmt.Println("[DEBUG]", msg)
}

// Info logs an informational message with [INFO] prefix
func (d *DefaultLogger) Info(msg string) {
	fmt.Println("[INFO]", msg)
}

// Warn logs a warning message with [WARN] prefix
func (d *DefaultLogger) Warn(msg string) {
	fmt.Println("[WARN]", msg)
}

// Error logs an error message with [ERROR] prefix
func (d *DefaultLogger) Error(msg string) {
	fmt.Println("[ERROR]", msg)
}

// Log logs a message with the given level
func (d *DefaultLogger) Log(level int, msg string) {
	switch level {
	case LogLevelDebug:
		d.Debug(msg)
	case LogLevelInfo:
		d.Info(msg)
	case LogLevelWarn:
		d.Warn(msg)
	case LogLevelError:
		d.Error(msg)
	default:
		fmt.Println("[UNKNOWN]", msg)
	}
}

// NewDefaultLogger creates a new DefaultLogger instance
func NewDefaultLogger() Logger {
	return &DefaultLogger{}
}
