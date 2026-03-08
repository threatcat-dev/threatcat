// Package logging provides factory functions for creating slog.Logger instances
// with various output configurations including console, file, dual (console+file),
// and discard modes. All loggers use slog.TextHandler for consistent formatting.
package logging

import (
	"io"
	"log/slog"
	"os"
	"sync"
)

// NewDualLogger creates an slog.Logger that writes to both the console and a file.
// This is useful for applications that need to maintain a persistent log file
// while also displaying logs in real-time on the console.
//
// Parameters:
//   - filePath: the path to the log file (must not be empty)
//   - level: the minimum log level to record (e.g., slog.LevelInfo, slog.LevelDebug)
//
// Returns:
//   - *slog.Logger: the configured dual-output logger
//   - func() error: a cleanup function that closes the file handle (must be called by caller)
//   - error: os.ErrInvalid if filePath is empty, or an error if the file cannot be opened
//
// The caller must call the cleanup function (typically with defer) to prevent resource leaks.
// The cleanup function is idempotent and safe to call multiple times.
// The log file is opened in append mode with permissions 0644.
//
// Example:
//
//	logger, cleanup, err := NewDualLogger("app.log", slog.LevelInfo)
//	if err != nil {
//		return err
//	}
//	defer func() {
//		if cleanup != nil {
//			if err := cleanup(); err != nil {
//				log.Printf("failed to close log file: %v", err)
//			}
//		}
//	}()
func NewDualLogger(filePath string, level slog.Level) (*slog.Logger, func() error, error) {
	// Validate input
	if filePath == "" {
		return nil, nil, os.ErrInvalid
	}

	// Open the log file for appending, create it if it doesn't exist
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, err
	}

	// Create a MultiWriter to write to both stdout and the file
	writer := io.MultiWriter(os.Stdout, file)

	// Create a text handler with the desired log level
	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: level,
	})

	// Create the logger
	logger := slog.New(handler)

	// Define idempotent cleanup function to close the file
	// Uses sync.Once to ensure Close is only called once
	var once sync.Once
	var closeErr error
	cleanup := func() error {
		once.Do(func() {
			closeErr = file.Close()
		})
		return closeErr
	}

	return logger, cleanup, nil
}

// NewConsoleLogger creates an slog.Logger that writes to the console (stdout).
// This logger is suitable for command-line applications or when file logging is not needed.
//
// Parameters:
//   - level: the minimum log level to record (e.g., slog.LevelInfo, slog.LevelDebug)
//
// Returns:
//   - *slog.Logger: a logger configured to write to stdout using slog.TextHandler
//
// This logger does not require cleanup as it writes to stdout, which is managed by the OS.
func NewConsoleLogger(level slog.Level) *slog.Logger {
	// Create a handler for console output
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	// Create the logger
	logger := slog.New(handler)

	return logger
}

// NewFileLogger creates an slog.Logger that writes exclusively to a file.
// Unlike NewDualLogger, this logger does not output to the console.
//
// Parameters:
//   - filePath: the path to the log file (must not be empty)
//   - level: the minimum log level to record (e.g., slog.LevelInfo, slog.LevelDebug)
//
// Returns:
//   - *slog.Logger: the configured file-only logger
//   - func() error: a cleanup function that closes the file handle (must be called by caller)
//   - error: os.ErrInvalid if filePath is empty, or an error if the file cannot be opened
//
// The caller must call the cleanup function (typically with defer) to prevent resource leaks.
// The cleanup function is idempotent and safe to call multiple times.
// The log file is opened in append mode with permissions 0644.
//
// Example:
//
//	logger, cleanup, err := NewFileLogger("app.log", slog.LevelInfo)
//	if err != nil {
//		return err
//	}
//	defer func() {
//		if cleanup != nil {
//			if err := cleanup(); err != nil {
//				log.Printf("failed to close log file: %v", err)
//			}
//		}
//	}()
func NewFileLogger(filePath string, level slog.Level) (*slog.Logger, func() error, error) {
	// Validate input
	if filePath == "" {
		return nil, nil, os.ErrInvalid
	}

	// Open the log file for appending, create it if it doesn't exist
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, err
	}

	// Create a text handler for file output
	handler := slog.NewTextHandler(file, &slog.HandlerOptions{
		Level: level,
	})

	// Create the logger
	logger := slog.New(handler)

	// Define idempotent cleanup function to close the file
	// Uses sync.Once to ensure Close is only called once
	var once sync.Once
	var closeErr error
	cleanup := func() error {
		once.Do(func() {
			closeErr = file.Close()
		})
		return closeErr
	}

	return logger, cleanup, nil
}

// NewDiscardLogger creates an slog.Logger that discards all log output.
// This logger silently ignores all log messages, providing zero overhead.
//
// Returns:
//   - *slog.Logger: a logger that discards all output to io.Discard
//
// Use cases:
//   - Unit tests where log output is not needed
//   - Production environments where logging must be completely disabled
//   - Performance-critical code where logging overhead must be eliminated
//
// This logger does not require cleanup.
func NewDiscardLogger() *slog.Logger {
	// Create a handler that discards all output
	handler := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug})
	// Create the logger
	logger := slog.New(handler)

	return logger
}
