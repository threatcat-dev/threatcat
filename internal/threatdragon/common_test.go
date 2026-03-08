package threatdragon

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// TestGenerateIDHash tests the generateIDHash function to ensure it produces non-empty hashes and equal hashes for same input.
func TestGenerateIDHash(t *testing.T) {
	tests := []struct {
		name               string
		filePath           string
		threatdragonCellID string
		expectedLen        int
	}{
		{
			name:               "Valid file path and CellID",
			filePath:           "/path/to/file",
			threatdragonCellID: uuid.NewString(),
			expectedLen:        common.MaxIDHashLength,
		},
		{
			name:               "Empty file path and CellID",
			filePath:           "",
			threatdragonCellID: "",
			expectedLen:        common.MaxIDHashLength,
		},
		{
			name:               "Long file path and CellID",
			filePath:           "/a/very/long/path/to/a/file/that/should/be/hashed",
			threatdragonCellID: uuid.NewString(),
			expectedLen:        common.MaxIDHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := generateIDHash(tt.filePath, tt.threatdragonCellID)
			secondHash := generateIDHash(tt.filePath, tt.threatdragonCellID) // Generate a second hash for comparison
			assert.Equal(t, hash, secondHash, "Hashes should be equal for the same input")
			assert.NotEmpty(t, hash, "Hash should not be empty")
			assert.Equal(t, tt.expectedLen, len(hash), fmt.Sprintf("Hash length should be %d characters", tt.expectedLen))
		})
	}
}

// TestExtractID tests the extraction of an AnalyzerID from a description string.
func TestExtractID(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expectedID  string
	}{
		{
			name:        "Valid AnalyzerID",
			description: "This is a test #AnalyzerID:1234567890abcdef1234567890abcdef#",
			expectedID:  "1234567890abcdef1234567890abcdef",
		},
		{
			name:        "No AnalyzerID",
			description: "This is a test without an ID",
			expectedID:  "",
		},
		{
			name:        "Malformed AnalyzerID",
			description: "This is a test #AnalyzerID:invalidhash123#",
			expectedID:  "",
		},
		{
			name:        "Multiple AnalyzerIDs",
			description: "This is a test #AnalyzerID:1234567890abcdef1234567890abcdef# and another #AnalyzerID:7890123456789abcdef7890123456789abcdef#",
			expectedID:  "1234567890abcdef1234567890abcdef", // Only the first match is returned
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractID(&tt.description, slog.Default())
			assert.Equal(t, tt.expectedID, result)
		})
	}
}
