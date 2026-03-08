package modelmerger

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/threatcat-dev/threatcat/internal/common"
)

// getUserInputAsUnsignedInt reads a numeric user input from stdin and returns it as uint.
//
// Input requirements:
//   - Must be a non-negative integer
//   - Leading and trailing whitespace is automatically trimmed
//   - Must fit within the platform's uint range
//
// Returns:
//   - The parsed unsigned integer value
//   - ErrEmptyInput if the input is empty or only whitespace
//   - An error if the input contains non-numeric characters, is negative,
//     is a floating-point number, or exceeds the maximum uint value
//
// Note: declared as var so it can be mocked in tests.
var getUserInputAsUnsignedInt = func() (uint, error) {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return 0, common.ErrEmptyInput
	}

	// Parse as int64 to catch all errors including floats
	result, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid input: expected non-negative integer, got: %s", trimmed)
	}

	// Check for non-negative
	if result < 0 {
		return 0, fmt.Errorf("expected non-negative integer, got: %d", result)
	}

	// Ensure result fits into uint (32 or 64 bit depending on platform)
	if uint64(result) > math.MaxUint {
		return 0, fmt.Errorf("value %d exceeds maximum uint value", result)
	}

	return uint(result), nil
}

// getUserInputAsText reads a text input from stdin and returns it as a trimmed string.
//
// The function reads until a newline character is encountered.
// Leading and trailing whitespace (including the newline) is removed from the result.
//
// Returns:
//   - The trimmed input string (may be empty if user only pressed Enter)
//   - An error if reading from stdin fails
//
// Note: declared as var so it can be mocked in tests.
var getUserInputAsText = func() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	input = strings.TrimSpace(input)
	return input, nil
}

// getUserConfirmation asks for user confirmation (y/n) and returns true for yes, false for no.
// It accepts optional strings to print as a prompt or context before the input line.
// This function asks the user repeatedly until a valid input is provided.
//
// Input handling:
//   - "y" or "Y" (case-insensitive) returns true
//   - "n" or "N" (case-insensitive) returns false
//   - Empty input (just pressing Enter) is treated as "y" and returns true
//   - Any other input results in an error message and re-prompt
//
// The function blocks until valid input is received and never returns an error.
func getUserConfirmation(prompt ...string) bool {
	// 1. Print any provided context/prompt
	if len(prompt) > 0 {
		fmt.Println("-----------------------------------------------------")
		for _, line := range prompt {
			fmt.Println(line)
		}
	}

	fmt.Println("Confirm (y/n): ")

	for {
		input, err := getUserInputAsText()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			continue
		}

		input = strings.ToLower(strings.TrimSpace(input))

		// Default to "y" on empty input
		if input == "" || input == "y" {
			return true
		} else if input == "n" {
			return false
		}

		fmt.Print("Invalid input, please enter 'y' or 'n': ")
	}
}
