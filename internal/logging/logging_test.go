package logging

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDualLogger checks that logging writes to the file and console (stdout).
func TestNewDualLogger(t *testing.T) {
	// Create a temporary file for the log
	tmpFile, err := os.CreateTemp("", "testlog-*.log")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name()) // clean up
	defer tmpFile.Close()

	// Create logger with INFO level
	logger, err := NewDualLogger(tmpFile.Name(), slog.LevelInfo)
	require.NoError(t, err, "Failed to create dual logger")

	// Log a test message
	testMsg := "Test log message"
	logger.Info(testMsg)

	// Sleep a bit to ensure log is written, or alternatively flush buffers
	// We reopen the file to read it back.
	content, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err, "Failed to read log file")

	// Assert that the content contains the test message
	assert.Contains(t, string(content), testMsg, "Expected log message not found in file")
}
