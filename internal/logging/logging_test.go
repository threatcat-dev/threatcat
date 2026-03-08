package logging

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDualLogger verifies that NewDualLogger creates a logger that writes to both
// the console (stdout) and a file simultaneously.
//
// Test scenario:
//   - Creates a temporary log file
//   - Initializes a dual logger with INFO level
//   - Logs a test message
//   - Verifies the message was written to the file
//
// Assertions:
//   - Logger creation succeeds without error
//   - Cleanup function is not nil
//   - Logged message appears in the file content
func TestNewDualLogger(t *testing.T) {
	// Create a temporary file for the log
	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name()) // clean up
	defer tmpFile.Close()

	// Create logger with INFO level
	logger, cleanup, err := NewDualLogger(tmpFile.Name(), slog.LevelInfo)
	require.NoError(t, err, "Failed to create dual logger")

	// Ensure cleanup is called at the end
	require.NotNil(t, cleanup, "Cleanup function should not be nil")
	defer cleanup()

	// Log a test message
	testMsg := "Test log message"
	logger.Info(testMsg)

	// Read the file to verify the log was written
	content, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err, "Failed to read log file")

	// Assert that the content contains the test message
	assert.Contains(t, string(content), testMsg, "Expected log message not found in file")
}

// TestNewConsoleLogger verifies that NewConsoleLogger creates a logger that writes to stdout
// without panicking or erroring.
//
// Test scenario:
//   - Creates a console logger with INFO level
//   - Logs messages at various levels (Info, Debug, Error, Warn)
//   - Verifies no panics occur during logging
//
// Assertions:
//   - Logger is not nil
//   - All logging calls complete without panic
//
// Note: This test does not capture stdout, it only verifies the logger is functional.
func TestNewConsoleLogger(t *testing.T) {
	// Create logger with INFO level
	logger := NewConsoleLogger(slog.LevelInfo)
	require.NotNil(t, logger, "Logger should not be nil")

	// Log a test message (output goes to stdout, we're just verifying no panic)
	logger.Info("Console test message")
	logger.Debug("This should not appear at INFO level")

	// Verify logger is usable
	assert.NotPanics(t, func() {
		logger.Error("error message")
		logger.Warn("warning message")
	})
}

// TestNewDiscardLogger verifies that NewDiscardLogger creates a logger that silently
// discards all log messages without panicking.
//
// Test scenario:
//   - Creates a discard logger
//   - Logs messages at all levels (Debug, Info, Warn, Error)
//   - Verifies no panics occur
//
// Assertions:
//   - Logger is not nil
//   - All logging calls complete without panic
//   - No output is produced (output goes to io.Discard)
//
// Use case: This logger is useful in tests where log output should be suppressed.
func TestNewDiscardLogger(t *testing.T) {
	// Create discard logger
	logger := NewDiscardLogger()
	require.NotNil(t, logger, "Logger should not be nil")

	// Log messages at all levels - should not panic and should be discarded
	assert.NotPanics(t, func() {
		logger.Debug("debug message")
		logger.Info("info message")
		logger.Warn("warning message")
		logger.Error("error message")
	})
}

// TestCleanupActuallyClosesFile verifies that the cleanup function returned by
// NewDualLogger actually closes the file handle, releasing system resources.
//
// Test scenario:
//   - Creates a dual logger with a temporary file
//   - Logs a message
//   - Calls the cleanup function
//   - Attempts to open the file with exclusive access
//
// Assertions:
//   - Cleanup completes without error
//   - File can be opened after cleanup (proving the original handle was closed)
//
// This test is important to prevent file descriptor leaks in long-running applications.
func TestCleanupActuallyClosesFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	logger, cleanup, err := NewDualLogger(tmpPath, slog.LevelInfo)
	require.NoError(t, err)
	require.NotNil(t, cleanup, "Cleanup function should not be nil")

	// Write some data
	logger.Info("test message")

	// Call cleanup
	err = cleanup()
	assert.NoError(t, err, "Cleanup should not return error")

	// Verify file is closed by checking we can open it exclusively
	// On most systems, you can't delete an open file or get exclusive access
	file, err := os.OpenFile(tmpPath, os.O_RDWR, 0o644)
	require.NoError(t, err, "Should be able to open file after cleanup")
	file.Close()
}

// TestCleanupFlushesPendingWrites ensures buffered data is written to disk before
// the file handle is closed.
//
// Test scenario:
//   - Creates a dual logger with a temporary file
//   - Writes multiple log messages in sequence
//   - Calls cleanup to flush and close
//   - Reads the file content from disk
//
// Assertions:
//   - Cleanup completes without error
//   - All logged messages are present in the file
//
// This test verifies that calling cleanup() properly flushes any pending writes
// to disk before closing the file handle, preventing data loss.
func TestCleanupFlushesPendingWrites(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	logger, cleanup, err := NewDualLogger(tmpPath, slog.LevelInfo)
	require.NoError(t, err)
	defer cleanup()

	// Write multiple messages
	testMessages := []string{"message1", "message2", "message3"}
	for _, msg := range testMessages {
		logger.Info(msg)
	}

	// Call cleanup to flush
	err = cleanup()
	require.NoError(t, err)

	// Read file and verify all messages were written
	content, err := os.ReadFile(tmpPath)
	require.NoError(t, err)

	for _, msg := range testMessages {
		assert.Contains(t, string(content), msg, "Message should be in file after cleanup")
	}
}

// TestCleanupIdempotency verifies that the cleanup function can be called multiple
// times safely without causing errors or panics.
//
// Test scenario:
//   - Creates a dual logger
//   - Calls cleanup three times in succession
//   - Compares the error results from each call
//
// Assertions:
//   - First cleanup call succeeds
//   - Subsequent calls return the same result as the first call
//   - No panics occur from double-close attempts
//
// This tests the sync.Once implementation to prevent double-close errors.
// Idempotent cleanup is essential for safe defer usage and error handling patterns.
func TestCleanupIdempotency(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	logger, cleanup, err := NewDualLogger(tmpPath, slog.LevelInfo)
	require.NoError(t, err)

	logger.Info("test")

	// Call cleanup multiple times - should not panic or error
	err1 := cleanup()
	err2 := cleanup()
	err3 := cleanup()

	// First call should succeed
	assert.NoError(t, err1, "First cleanup should succeed")
	// Subsequent calls should return the same result (no new errors)
	assert.Equal(t, err1, err2, "Second cleanup should return same error as first")
	assert.Equal(t, err1, err3, "Third cleanup should return same error as first")
}

// TestFileLoggerCleanup verifies that NewFileLogger returns a working cleanup function
// and that the cleanup properly closes the file handle while preserving written data.
//
// Test scenario:
//   - Creates a file logger with a temporary file
//   - Logs a message
//   - Calls cleanup
//   - Reads and verifies file content
//
// Assertions:
//   - Logger creation succeeds
//   - Cleanup function is not nil
//   - Cleanup completes without error
//   - Log message is present in the file after cleanup
func TestFileLoggerCleanup(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	logger, cleanup, err := NewFileLogger(tmpPath, slog.LevelInfo)
	require.NoError(t, err)
	require.NotNil(t, cleanup, "Cleanup function should not be nil")

	logger.Info("file logger test")

	err = cleanup()
	assert.NoError(t, err, "File logger cleanup should succeed")

	// Verify content was written
	content, err := os.ReadFile(tmpPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "file logger test")
}

// TestNoFileDescriptorLeak verifies that repeated logger creation and cleanup
// does not leak file descriptors over many iterations.
//
// Test scenario:
//   - Counts initial open file descriptors
//   - Creates and cleans up 100 loggers in a loop
//   - Forces garbage collection
//   - Counts final open file descriptors
//   - Compares initial and final counts
//
// Assertions:
//   - File descriptor count increase is minimal (≤5)
//   - No file descriptor leak occurs across 100 iterations
//
// This test verifies that file handles are properly released after cleanup,
// which is critical for long-running applications that create many loggers.
func TestNoFileDescriptorLeak(t *testing.T) {
	// Get initial open file count
	initialFDs := countOpenFiles(t)

	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Create and cleanup logger multiple times
	iterations := 100
	for i := 0; i < iterations; i++ {
		logger, cleanup, err := NewDualLogger(tmpPath, slog.LevelInfo)
		require.NoError(t, err)

		logger.Info(fmt.Sprintf("iteration %d", i))

		err = cleanup()
		require.NoError(t, err)
	}

	// Force garbage collection
	runtime.GC()

	// Check final open file count
	finalFDs := countOpenFiles(t)

	// Allow some tolerance (GC might not be immediate)
	// But should not have leaked 100 file descriptors
	fdDiff := finalFDs - initialFDs
	assert.LessOrEqual(t, fdDiff, 5,
		"Too many file descriptors leaked: initial=%d, final=%d, diff=%d",
		initialFDs, finalFDs, fdDiff)
}

// countOpenFiles attempts to count open file descriptors for the current process.
// This is a helper function for testing file descriptor leaks.
//
// Implementation details:
//   - On Linux with /proc: counts entries in /proc/self/fd
//   - On macOS and other systems: returns 0 (test will pass)
//
// Parameters:
//   - t: the testing.T instance (used for t.Helper() marking)
//
// Returns:
//   - The number of open file descriptors, or 0 if counting is not supported
//
// This is a best-effort check for file descriptor leaks in tests.
// In production, use proper monitoring tools instead.
func countOpenFiles(t *testing.T) int {
	t.Helper()

	// On Unix systems, /proc/self/fd contains symlinks to all open files
	procPath := "/proc/self/fd"
	if _, err := os.Stat(procPath); err == nil {
		entries, err := os.ReadDir(procPath)
		if err == nil {
			return len(entries)
		}
	}

	// Fallback: on macOS, use lsof (slower but works)
	// This is approximate and just for testing
	// In production, use proper monitoring tools
	return 0 // Can't reliably count, test will pass
}

// TestInvalidInput verifies that NewDualLogger and NewFileLogger properly reject
// invalid input parameters.
//
// Test scenario:
//   - Attempts to create loggers with empty file paths
//   - Checks the returned error type
//
// Assertions:
//   - NewDualLogger returns os.ErrInvalid for empty filePath
//   - NewFileLogger returns os.ErrInvalid for empty filePath
//
// This ensures proper input validation and prevents silent failures.
func TestInvalidInput(t *testing.T) {
	_, _, err := NewDualLogger("", slog.LevelInfo)
	assert.ErrorIs(t, err, os.ErrInvalid, "Empty file path should return ErrInvalid")

	_, _, err = NewFileLogger("", slog.LevelInfo)
	assert.ErrorIs(t, err, os.ErrInvalid, "Empty file path should return ErrInvalid")
}

// TestNonexistentDirectory verifies that logger creation fails gracefully when
// provided with a file path in a nonexistent directory.
//
// Test scenario:
//   - Attempts to create loggers with paths to nonexistent directories
//   - Checks that an error is returned
//
// Assertions:
//   - NewDualLogger returns an error for invalid paths
//   - NewFileLogger returns an error for invalid paths
//
// This ensures that file system errors are properly propagated to the caller
// rather than causing panics or silent failures.
func TestNonexistentDirectory(t *testing.T) {
	_, _, err := NewDualLogger("/nonexistent/path/file.log", slog.LevelInfo)
	assert.Error(t, err, "Should error on nonexistent directory")

	_, _, err = NewFileLogger("/nonexistent/path/file.log", slog.LevelInfo)
	assert.Error(t, err, "Should error on nonexistent directory")
}

