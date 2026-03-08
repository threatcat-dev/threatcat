package threatdragon

import (
	"fmt"
	"log/slog"
	"slices"
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
		expectError   bool
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
				Boundaries: []common.TrustBoundary{
					{
						ID:              "", // ID is not checked
						DisplayName:     "Boundary Name",
						ContainedAssets: []string{}, // ContainedAssets is not Checked
						Source:          common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
				},
			},
			expectError: false,
		},
		{
			testname:      "test analyze parsed for empty model",
			inputFile:     "./testdata/threatdragon_empty.json",
			expectedModel: common.EmptyThreatModel(), // not used since an error is expected
			expectError:   true,
		},
		{
			testname:      "test analyze parsed for malformed JSON",
			inputFile:     "./testdata/threatdragon_malformed.json",
			expectedModel: common.EmptyThreatModel(), // not used since an error is expected
			expectError:   true,
		},
		{
			testname:      "test analyze parsed for missing fields in JSON",
			inputFile:     "./testdata/threatdragon_missing_fields.json",
			expectedModel: common.EmptyThreatModel(), // not used since an error is expected
			expectError:   true,
		},
		{
			testname:      "test analyze parsed for duplicate ids",
			inputFile:     "./testdata/threatdragon_duplicate_ids.json",
			expectedModel: common.EmptyThreatModel(), // not used since an error is expected
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.testname+":"+tt.inputFile, func(t *testing.T) {
			// Create a new analyzer instance
			input := NewThreatDragonInput(tt.inputFile, slog.Default())

			// Analyze the parsed threat model
			internalModel, err := input.Analyze()
			if tt.expectError {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err, "Expected no error, got %v", err)
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

			assert.Equal(t, len(tt.expectedModel.Boundaries), len(internalModel.Boundaries))
			// Validate each trust boundary's properties
			for i, boundary := range internalModel.Boundaries {
				assert.Equal(t, common.MaxIDHashLength, len(boundary.ID)) // Ensure ID length
				assert.Equal(t, tt.expectedModel.Boundaries[i].DisplayName, boundary.DisplayName)
			}
		})
	}
}

func TestAnalyzeWithBoundary(t *testing.T) {
	tests := []struct {
		testname      string
		inputFile     string
		expectedModel common.ThreatModel
	}{
		{
			testname:  "test analyze threatdragon file with trust boundary",
			inputFile: "./testdata/threatdragon_trustboundary_testjson.json",
			expectedModel: common.ThreatModel{
				Assets: []common.Asset{
					{
						ID:          "d899870e-853e-4378-aea1-c2c9d489e16f",
						DisplayName: "Process in TB1",
						Type:        common.AssetTypeApplication,
						Source:      common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
					{
						ID:          "7a065373-8d89-4fe2-a1cc-cdf6cd7aa1ba",
						DisplayName: "Store in TB1",
						Type:        common.AssetTypeDatabase,
						Source:      common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
					{
						ID:          "6e101964-58e8-4379-893a-a358ca1c086e",
						DisplayName: "Process in TB2",
						Type:        common.AssetTypeApplication,
						Source:      common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
					{
						ID:          "32607f61-2ccf-4a34-be65-c4bb6ef7243b",
						DisplayName: "Store outside of TB",
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
				Boundaries: []common.TrustBoundary{
					{
						ID:          "", // ID is not checked
						DisplayName: "Trust Boundary 1",
						ContainedAssets: []string{
							generateIDHash("./testdata/threatdragon_trustboundary_testjson.json", "d899870e-853e-4378-aea1-c2c9d489e16f"),
							generateIDHash("./testdata/threatdragon_trustboundary_testjson.json", "7a065373-8d89-4fe2-a1cc-cdf6cd7aa1ba"),
						},
						Source: common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
					{
						ID:          "", // ID is not checked
						DisplayName: "Trust Boundary 2",
						ContainedAssets: []string{
							generateIDHash("./testdata/threatdragon_trustboundary_testjson.json", "6e101964-58e8-4379-893a-a358ca1c086e"),
						},
						Source: common.DataSourceThreatDragon,
						Extra: map[string]any{
							"ThreatDragonCell": map[string]any{}, // Not checked
						},
					},
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

			// Validate each trust boundary's properties
			assert.Equal(t, len(tt.expectedModel.Boundaries), len(internalModel.Boundaries))
			for i, boundary := range internalModel.Boundaries {
				assert.Equal(t, common.MaxIDHashLength, len(boundary.ID))                                           // Ensure ID length
				assert.Equal(t, len(tt.expectedModel.Boundaries[i].ContainedAssets), len(boundary.ContainedAssets)) // Ensure ContainedAssets length

				for _, id := range tt.expectedModel.Boundaries[i].ContainedAssets {
					assert.True(t, slices.Contains(boundary.ContainedAssets, id))
				}

				assert.Equal(t, tt.expectedModel.Boundaries[i].DisplayName, boundary.DisplayName)
			}
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
		expectedIDLength   int
	}{
		{
			name:               "Valid file path and cellID",
			filePath:           "/path/to/file",
			threatdragonCellID: uuid.NewString(),
			expectedIDLength:   common.MaxIDHashLength,
		},
		{
			name:               "Empty file path and cellID",
			filePath:           "",
			threatdragonCellID: "",
			expectedIDLength:   common.MaxIDHashLength,
		},
		{
			name:               "Long file path and cellID",
			filePath:           "/a/very/long/path/to/a/file/that/should/be/hashed",
			threatdragonCellID: uuid.NewString(),
			expectedIDLength:   common.MaxIDHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := generateIDHash(tt.filePath, tt.threatdragonCellID)

			// basic checks
			assert.NotEmpty(t, id, "ID should not be empty")

			// id should have expected length and format
			assert.Equal(t, tt.expectedIDLength, len(id), "ID should have the expected length")
			assert.Regexp(t, fmt.Sprintf(`^[0-9a-fA-F]{%d}$`, tt.expectedIDLength), id, "ID should match the expected format")
		})
	}
}

// TestGetCellDataThreats tests the extraction and generation of threats from cell data.
func TestGetCellDataThreats(t *testing.T) {
	filePath := "some/path/to/file"

	// create a stored threat (contains analyzer ID tag in description)
	id := "t-stored"
	storedID := generateIDHash(filePath, id)
	stored := Threat{
		ID:          id,
		Title:       "StoredThreat",
		Number:      Nullable[int64]{Value: 1, Set: true, Present: true},
		ModelType:   "STRIDE",
		Score:       Nullable[string]{Value: "1.0", Set: true, Present: true},
		Description: analyzerIDTag(storedID),
	}

	// create a user-created threat (no analyzer tag)
	user := Threat{
		ID:          "t-user",
		Title:       "UserThreat",
		ModelType:   "STRIDE",
		Number:      Nullable[int64]{Value: 2, Set: true, Present: true},
		Score:       Nullable[string]{Value: "2.0", Set: true, Present: true},
		Description: "",
	}

	data := Data{
		Threats: &[]Threat{stored, user},
	}

	threats, modelMap := getCellDataThreats(data, slog.Default(), filePath)

	assert.Len(t, threats, 2, "expected two threats returned")

	// stored threat should keep the extracted internal ID and be present in modelMap
	assert.Equal(t, storedID, threats[0].InternalID, "stored threat internal ID should match extracted ID")
	assert.False(t, threats[0].IsGeneratedByUser, "stored threat must not be marked as generated by user")
	_, ok := modelMap[0]
	assert.True(t, ok, "modelMap should contain stored threat")
	if ok {
		assert.Equal(t, stored.ID, modelMap[0].ID, "modelMap entry should reference original idx")
	}
	_, ok = modelMap[1]
	assert.True(t, ok, "modelMap should contain not stored threat")
	if ok {
		assert.Equal(t, user.ID, modelMap[1].ID, "modelMap entry should reference original idx")
	}

	// user-created threat should get a generated internal ID and be marked as generated by user
	expectedUserID := generateIDHash(filePath, user.ID)
	assert.Equal(t, expectedUserID, threats[1].InternalID, "user threat internal ID should be generated from filePath+threat.ID")
	assert.True(t, threats[1].IsGeneratedByUser, "user threat must be marked as generated by user")
}

// TestGetCellDataThreats_NoThreats tests the behavior of getCellDataThreats when no threats are present.
func TestGetCellDataThreats_NoThreats(t *testing.T) {
	data := Data{
		Threats: nil,
	}
	threats, modelMap := getCellDataThreats(data, slog.Default(), "some/path")
	assert.Equal(t, 0, len(threats), "expected no threats returned when data.Threats is nil")
	assert.Equal(t, 0, len(modelMap), "expected empty model map when data.Threats is nil")
}

// TestAnalyzeDataFlows tests the Analyze function's ability to parse data flows from a Threat Dragon model.
func TestAnalyzeDataFlows(t *testing.T) {
	// Use existing testdata file used by other tests
	input := NewThreatDragonInput("./testdata/models/three_tier_webapp_app.json", slog.Default())

	model, err := input.Analyze()
	if err != nil {
		assert.NoError(t, err)
	}

	// Expect at least one dataflow in the model
	assert.Greater(t, len(model.DataFlows), 0, "expected at least one DataFlow parsed")

	// Validate each dataflow basic properties and ID lengths
	for _, df := range model.DataFlows {
		assert.NotEmpty(t, df.ID, "DataFlow.ID should not be empty")
		assert.Equal(t, common.MaxIDHashLength, len(df.ID), "DataFlow.ID should have expected length")

		// Source and Target should have been replaced by internal asset IDs (length check)
		assert.Equal(t, common.MaxIDHashLength, len(df.SourceID), "DataFlow.Source should be an internal ID but was %s", df.SourceID)
		assert.Equal(t, common.MaxIDHashLength, len(df.TargetID), "DataFlow.Target with id %s should be an internal asset ID but was %s", df.ID, df.TargetID)
	}

	// Ensure that each DataFlow's Source and Target correspond to an asset in the model
	for _, df := range model.DataFlows {
		foundSrc := false
		foundTgt := false
		for _, a := range model.Assets {
			if a.ID == df.SourceID {
				foundSrc = true
			}
			if a.ID == df.TargetID {
				foundTgt = true
			}
			if foundSrc && foundTgt {
				break
			}
		}
		assert.Equal(t, true, foundSrc, "Source asset not found for DataFlow %s (source=%s)", df.ID, df.SourceID)
		assert.Equal(t, true, foundTgt, "Target asset not found for DataFlow %s (target=%s)", df.ID, df.TargetID)
	}
}

// TestFindCorrespondingAsset verifies that findCorrespondingAsset returns the extracted analyzer ID
// when present in the cell description and falls back to a generated hash when not present.
// It also checks behavior for empty idToFind.
func TestFindCorrespondingAsset(t *testing.T) {
	logger := slog.Default()
	filePath := "filePath"

	// prepare cells: one with an embedded analyzer ID, one without
	storedID := generateIDHash(filePath, "cellA")
	descWithID := analyzerIDTag(storedID)
	cells := []Cell{
		{ID: "cellA", Data: Data{Description: &descWithID}},
		{ID: "cellB", Data: Data{Description: nil}},
	}

	// existing cell with stored analyzer ID should return that ID
	resA := findCorrespondingAsset("cellA", cells, filePath, logger)
	assert.Equal(t, storedID, resA)

	// existing cell without analyzer ID should return generated hash based on its cell ID
	expectedB := generateIDHash(filePath, "cellB")
	resB := findCorrespondingAsset("cellB", cells, filePath, logger)
	assert.Equal(t, expectedB, resB)

	// empty lookup should return empty string
	empty := findCorrespondingAsset("", cells, filePath, logger)
	assert.Equal(t, "", empty)
}

// TestReplaceSourceTargetAssetidsWithinternalIDs tests the replacement of target and source with hashed internal IDs
func TestReplaceSourceTargetAssetidsWithinternalIDs(t *testing.T) {
	filepath := "path/to/threatdragon.json"

	s1 := "service1"
	s2 := "service2"
	s3 := "service3"

	id1 := common.GenerateIDHashFromFilePath(filepath, s1)
	id2 := common.GenerateIDHashFromFilePath(filepath, s2)
	id3 := common.GenerateIDHashFromFilePath(filepath, s3)

	dfs := []common.DataFlow{
		{
			SourceID: s1,
			TargetID: s2,
		},
		{
			SourceID: s2,
			TargetID: s3,
		},
	}

	cells := []Cell{
		{ID: s1, Data: Data{}},
		{ID: s2, Data: Data{}},
		{ID: s3, Data: Data{}},
	}

	replaceSourceTargetAssetIdsWithInternalIDs(dfs, cells, filepath, slog.Default())

	assert.Equal(t, id1, dfs[0].SourceID)
	assert.Equal(t, id2, dfs[0].TargetID)
	assert.Equal(t, id2, dfs[1].SourceID)
	assert.Equal(t, id3, dfs[1].TargetID)

}
