package logging

import (
	"io"
	"log/slog"
	"os"
)

// NewDualLogger creates an slog.Logger that writes to both the console and a file.
func NewDualLogger(filePath string, level slog.Level) (*slog.Logger, error) {
	// Open the log file for appending, create it if it doesn't exist
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	// Create a MultiWriter to write to both stdout and the file
	writer := io.MultiWriter(os.Stdout, file)

	// Create a handler with the desired level and JSON format
	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: level,
	})

	// Create the logger
	logger := slog.New(handler)

	return logger, nil
}

// NewConsoleLogger creates an slog.Logger that writes to the console.
func NewConsoleLogger(level slog.Level) *slog.Logger {
	// Create a handler for console output
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	// Create the logger
	logger := slog.New(handler)

	return logger
}

// NewFileLogger creates an slog.Logger that writes to a file.
func NewFileLogger(filePath string, level slog.Level) (*slog.Logger, error) {

	// Open the log file for appending, create it if it doesn't exist
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	// Create a handler for console output
	handler := slog.NewTextHandler(file, &slog.HandlerOptions{
		Level: level,
	})
	// Create the logger
	logger := slog.New(handler)

	return logger, nil
}

// NewDiscardLogger disables logging entirely.
func NewDiscardLogger() *slog.Logger {

	// Create a handler for console output
	handler := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug})
	// Create the logger
	logger := slog.New(handler)

	return logger
}
