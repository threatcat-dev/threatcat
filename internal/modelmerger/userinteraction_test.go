package modelmerger

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// TestGetUserInputAsUnsignedInt verifies getUserInputAsUnsignedInt correctly
// parses and validates user input by mocking stdin.
//
// Test cases:
//   - Valid positive integer (42)
//   - Zero (valid edge case)
//   - Large number (999999)
//   - Negative number (should be rejected)
//   - Non-numeric input ("abc")
//   - Float input (3.14, should be rejected)
//   - Empty input (just newline)
//   - Whitespace with valid number (should trim and parse)
//
// This test uses temporary files to simulate stdin input, allowing
// comprehensive testing without actual user interaction.
func TestGetUserInputAsUnsignedInt(t *testing.T) {
	// Save original and restore after test
	oldFn := getUserInputAsUnsignedInt
	defer func() { getUserInputAsUnsignedInt = oldFn }()

	tests := []struct {
		name        string
		input       string
		expectError bool
		expected    uint
		errorIs     error
		errorMsg    string
	}{
		{
			name:     "Valid positive integer",
			input:    "42\n",
			expected: 42,
		},
		{
			name:     "Zero is valid",
			input:    "0\n",
			expected: 0,
		},
		{
			name:     "Large number",
			input:    "999999\n",
			expected: 999999,
		},
		{
			name:        "Negative number rejected",
			input:       "-5\n",
			expectError: true,
			errorMsg:    "expected non-negative integer, got: -5",
		},
		{
			name:        "Non-numeric input",
			input:       "abc\n",
			expectError: true,
		},
		{
			name:        "Float input",
			input:       "3.14\n",
			expectError: true,
		},
		{
			name:        "Empty input",
			input:       "\n",
			expectError: true,
			errorIs:     common.ErrEmptyInput,
		},
		{
			name:     "Whitespace with valid number",
			input:    "  42  \n",
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to simulate stdin
			tmpFile, err := os.CreateTemp("", "stdin-*.txt")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			_, err = tmpFile.WriteString(tt.input)
			require.NoError(t, err)
			_, err = tmpFile.Seek(0, 0)
			require.NoError(t, err)

			// Replace stdin temporarily
			oldStdin := os.Stdin
			os.Stdin = tmpFile
			defer func() { os.Stdin = oldStdin }()

			// Reset to the real implementation for this test
			getUserInputAsUnsignedInt = oldFn

			result, err := getUserInputAsUnsignedInt()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetUserConfirmation(t *testing.T) {
	// Save original and restore after test
	oldInput := getUserInputAsText
	defer func() { getUserInputAsText = oldInput }()

	tests := []struct {
		name       string
		mockInputs []string // Simulated sequence of user entries
		want       bool
	}{
		{"Accept on empty", []string{""}, true},
		{"Accept on y", []string{"y"}, true},
		{"Accept on Y uppercase", []string{"Y"}, true},
		{"Reject on n", []string{"n"}, false},
		{"Retry on invalid then accept", []string{"invalid", "y"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mocking the input sequence
			inputCounter := 0
			getUserInputAsText = func() (string, error) {
				val := tt.mockInputs[inputCounter]
				inputCounter++
				return val, nil
			}

			got := getUserConfirmation("Test Prompt")
			if got != tt.want {
				t.Errorf("getUserConfirmation() = %v, want %v", got, tt.want)
			}
		})
	}
}
