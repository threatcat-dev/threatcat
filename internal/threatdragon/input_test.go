package threatdragon

import (
	"fmt"
	"log/slog"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// TestAnalyze tests the Analyze function of the ThreatdragonAnalyzer.
// It verifies that the parsed threat model matches the expected internal model structure.
func TestAnalyze(t *testing.T) {
	tests := []struct {
		testname      string
		inputFile     string
		expectedModel common.ThreatModel
	}{
		{
			testname:  "test analyze parsed threatdragon file for dynamic input",
			inputFile: "./testdata/threatdragon_dynamicIn.json",
			expectedModel: common.ThreatModel{
				Assets: []common.Asset{
					{
						ID:          "", // ID is not checked
						DisplayName: "Process Name",
						Type:        common.AssetTypeApplication,
						Source:      common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
					{
						ID:          "", // ID is not checked
						DisplayName: "Store Name",
						Type:        common.AssetTypeDatabase,
						Source:      common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
				},
				Extra: map[string]any{
					"ThreatDragonModel": nil, // Not checked
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testname+":"+tt.inputFile, func(t *testing.T) {
			// Create a new analyzer instance
			input := NewThreatDragonInput(tt.inputFile, slog.Default())

			// Analyze the parsed threat model
			internalModel, err := input.Analyze()
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			// Validate the number of assets and diagram IDs
			assert.Equal(t, len(tt.expectedModel.Assets), len(internalModel.Assets))

			// Sort assets by display name for comparison
			sort.Slice(tt.expectedModel.Assets, func(i, j int) bool {
				return tt.expectedModel.Assets[i].DisplayName < tt.expectedModel.Assets[j].DisplayName
			})
			sort.Slice(internalModel.Assets, func(i, j int) bool {
				return internalModel.Assets[i].DisplayName < internalModel.Assets[j].DisplayName
			})

			// Validate each asset's properties
			for i, asset := range internalModel.Assets {
				assert.Equal(t, common.MaxIDHashLength, len(asset.ID)) // Ensure ID length
				assert.Equal(t, tt.expectedModel.Assets[i].DisplayName, asset.DisplayName)
				assert.Equal(t, tt.expectedModel.Assets[i].Type, asset.Type)
			}
		})
	}
}

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

// TestIsRelevantType tests if a cell type is relevant for analysis.
func TestIsRelevantType(t *testing.T) {
	tests := []struct {
		name     string
		cellType string
		expected bool
	}{
		{
			name:     "Relevant type: tm.Process",
			cellType: "tm.Process",
			expected: true,
		},
		{
			name:     "Relevant type: tm.Store",
			cellType: "tm.Store",
			expected: true,
		},
		{
			name:     "Irrelevant type: tm.Flow",
			cellType: "tm.Flow",
			expected: false,
		},
		{
			name:     "Irrelevant type: tm.Actor",
			cellType: "tm.Actor",
			expected: false,
		},
		{
			name:     "Irrelevant type: tm.Boundary",
			cellType: "tm.Boundary",
			expected: false,
		},
		{
			name:     "Unknown type",
			cellType: "unknown.Type",
			expected: false, // Default behavior for unknown types
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRelevantType(tt.cellType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGetCellDataType tests the mapping of cell data to asset types.
func TestGetCellDataType(t *testing.T) {
	tests := []struct {
		name     string
		data     Data
		expected common.AssetType
	}{
		{
			name: "Web application process",
			data: Data{
				Type:             "tm.Process",
				IsWebApplication: boolPtr(true),
			},
			expected: common.AssetTypeApplication,
		},
		{
			name: "Non-web application process",
			data: Data{
				Type:             "tm.Process",
				IsWebApplication: boolPtr(false),
			},
			expected: common.AssetTypeApplication,
		},
		{
			name: "Store type",
			data: Data{
				Type: "tm.Store",
			},
			expected: common.AssetTypeDatabase,
		},
		{
			name: "Unknown type",
			data: Data{
				Type: "unknown.Type",
			},
			expected: common.AssetTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCellDataType(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateInternalIDWithTag(t *testing.T) {
	tests := []struct {
		name               string
		filePath           string
		threatdragonCellID string
		expectedTagPrefix  string
		expectedIDLength   int
	}{
		{
			name:               "Valid file path and cellID",
			filePath:           "/path/to/file",
			threatdragonCellID: uuid.NewString(),
			expectedTagPrefix:  " #AnalyzerID:",
			expectedIDLength:   common.MaxIDHashLength,
		},
		{
			name:               "Empty file path and cellID",
			filePath:           "",
			threatdragonCellID: "",
			expectedTagPrefix:  " #AnalyzerID:",
			expectedIDLength:   common.MaxIDHashLength,
		},
		{
			name:               "Long file path and cellID",
			filePath:           "/a/very/long/path/to/a/file/that/should/be/hashed",
			threatdragonCellID: uuid.NewString(),
			expectedTagPrefix:  " #AnalyzerID:",
			expectedIDLength:   common.MaxIDHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idWithTag, id := generateInternalIDWithTag(tt.filePath, tt.threatdragonCellID, slog.Default())

			// Validate the ID with tag
			assert.True(t, len(idWithTag) > len(tt.expectedTagPrefix), "ID with tag should be longer than the prefix")
			assert.Regexp(t, fmt.Sprintf(`^#AnalyzerID:[0-9a-fA-F]{%d}#$`, tt.expectedIDLength), idWithTag, "ID with tag should match the expected format")

			// Validate the ID
			assert.Equal(t, tt.expectedIDLength, len(id), "ID should have the expected length")
			assert.Regexp(t, fmt.Sprintf(`^[0-9a-fA-F]{%d}$`, tt.expectedIDLength), id, "ID should match the expected format")
		})
	}
}
