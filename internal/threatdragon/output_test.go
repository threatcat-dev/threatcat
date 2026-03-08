package threatdragon

import (
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatcat-dev/threatcat/internal/common"
)

type dummyChangelog struct{}

func (dc dummyChangelog) AddEntry(string) {}

func TestGenerate(t *testing.T) {
	newThreatDragonOutput := NewThreatdragonOutput("./testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	model := common.EmptyThreatModel()
	model.Assets = []common.Asset{{Type: common.AssetTypeApplication, ID: "0", DisplayName: "new process 0"}}

	err := newThreatDragonOutput.Generate(&model)
	require.NoError(t, err)
}

func TestGenerateExistingModel(t *testing.T) {
	newThreatDragonOutput := NewThreatdragonOutput("./testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	model := common.EmptyThreatModel()
	model.Extra["ThreatDragonModel"] = *newProject()
	model.Assets = []common.Asset{{Type: common.AssetTypeApplication, ID: "0", DisplayName: "new process 0"}}

	err := newThreatDragonOutput.Generate(&model)
	require.NoError(t, err)
}

func TestUnmarshalAndMarshal(t *testing.T) {
	input, err := os.ReadFile("./testdata/threatdragon_one_asset.json")
	require.NoError(t, err)
	require.NotEmpty(t, input)

	newJsonStruct := Project{}
	err = json.Unmarshal(input, &newJsonStruct)
	require.NoError(t, err)

	output, err := json.MarshalIndent(&newJsonStruct, "", "  ")
	require.NoError(t, err)

	assert.JSONEq(t, string(input), string(output))
}

func TestUnmarshalAndMarshalDynamicFiles(t *testing.T) {

	tests := []struct {
		testname   string
		inputFile  string
		outputFile string
	}{
		{
			"test marshal and unmarshal dynamic files",
			"./testdata/threatdragon_dynamicIn.json",
			"./testdata/testoutput_threatdragon_dynamic.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testname+":"+tt.inputFile, func(t *testing.T) {
			newJsonStruct := Project{}

			inputData, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			err = json.Unmarshal(inputData, &newJsonStruct)
			require.NoError(t, err)

			outputData, err := json.MarshalIndent(&newJsonStruct, "", "    ")
			require.NoError(t, err)

			assert.JSONEq(t, string(inputData), string(outputData))

			err = os.WriteFile(tt.outputFile, outputData, 0644)
			require.NoError(t, err)
		})
	}
}

func TestAssetTypeToThreatdragonAssetInfoWithValidAsset(t *testing.T) {
	_, err := assetTypeToThreatdragonAssetInfo(common.AssetTypeDatabase)

	require.NoError(t, err)
}

func TestAssetTypeToThreatdragonAssetInfoWithUnkownAsset(t *testing.T) {
	processAsset, err := assetTypeToThreatdragonAssetInfo(common.AssetTypeApplication)
	require.NoError(t, err)
	unkownAsset, err := assetTypeToThreatdragonAssetInfo(common.AssetTypeUnknown)
	require.NoError(t, err)

	assert.Equal(t, processAsset, unkownAsset)
}

func TestAssetTypeToThreatdragonAssetInfoWithInvalidAsset(t *testing.T) {
	_, err := assetTypeToThreatdragonAssetInfo(999999)

	assert.Equal(t, err, ErrAssetTypeNoMapping)
}

func TestDefaultPortGroup(t *testing.T) {
	testName := "testName"
	portGroup := defaultPortGroup(testName)

	assert.Equal(t, portGroup.Position, testName)
	assert.Equal(t, portGroup.Attrs.Circle.R, 4.0)
	assert.Equal(t, portGroup.Attrs.Circle.Magnet, true)
	assert.Equal(t, portGroup.Attrs.Circle.Stroke, "#5F95FF")
	assert.Equal(t, portGroup.Attrs.Circle.StrokeWidth, 1.0)
	assert.Equal(t, portGroup.Attrs.Circle.Fill, "#fff")
	assert.Equal(t, portGroup.Attrs.Circle.Style.Visibility, "hidden")
}

func TestGenerateCellsWithNoAsset(t *testing.T) {
	emptyCells := []Cell{}
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	cs := newSimplePlacement()
	cells, err := tdo.generatePlaceNewCellsAndDataflows(nil, []common.Asset{}, []common.DataFlow{}, cs)
	require.NoError(t, err)

	assert.Equal(t, emptyCells, cells)
}

func TestGenerateCellsWithOneAsset(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	cells, err := tdo.generatePlaceNewCellsAndDataflows(nil, []common.Asset{{Type: common.AssetTypeDatabase}}, nil, dontPlace{})
	require.NoError(t, err)

	assert.Equal(t, 1, len(cells))
}

func TestGenerateCellsWithMultipleAsset(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	internalID1 := generateIDHash("somePath", "id-1")
	internalID2 := generateIDHash("somePath", "id-2")

	assets := []common.Asset{
		{DisplayName: "DB1",
			ID:   internalID1,
			Type: common.AssetTypeDatabase},
		{DisplayName: "App1",
			ID:   internalID2,
			Type: common.AssetTypeApplication},
		{Type: common.AssetTypeUnknown},
		{Type: common.AssetTypeInfrastructure},
	}
	dataFlows := []common.DataFlow{
		{
			Name:          "DF1",
			SourceID:      internalID2,
			TargetID:      internalID1,
			Bidirectional: true,
		},
		{
			Name:          "DF2",
			SourceID:      internalID1,
			TargetID:      internalID2,
			Bidirectional: false,
		},
	}
	cells, err := tdo.generatePlaceNewCellsAndDataflows(nil, assets, dataFlows, dontPlace{})
	require.NoError(t, err)

	assert.Equal(t, len(dataFlows)+len(assets), len(cells))
	dataFlowCell := cells[len(cells)-2]
	assert.Equal(t, "flow", dataFlowCell.Shape)
	assert.Equal(t, "DF1", *dataFlowCell.Labels[0].String)
	assert.Equal(t, true, *dataFlowCell.Data.IsBidirectional)
	assert.Equal(t, "block", dataFlowCell.Attrs.Line.SourceMarker.Contributor.Name)
	assert.Equal(t, "block", dataFlowCell.Attrs.Line.TargetMarker.Contributor.Name)
	assert.Equal(t, cells[0].ID, *dataFlowCell.Target.Cell)
	assert.Equal(t, cells[1].ID, *dataFlowCell.Source.Cell)
	dataFlowCell = cells[len(cells)-1]
	assert.Equal(t, "flow", dataFlowCell.Shape)
	assert.Equal(t, "DF2", *dataFlowCell.Labels[0].String)
	assert.Equal(t, false, *dataFlowCell.Data.IsBidirectional)
	assert.Equal(t, "", dataFlowCell.Attrs.Line.SourceMarker.Contributor.Name)
	assert.Equal(t, "block", dataFlowCell.Attrs.Line.TargetMarker.Contributor.Name)
	assert.Equal(t, cells[0].ID, *dataFlowCell.Source.Cell)
	assert.Equal(t, cells[1].ID, *dataFlowCell.Target.Cell)
}

// TestUpdateCell_TypeSwitchAndFieldCopy tests the updateCell function for type switching and field copying to loose no data
func TestUpdateCell_TypeSwitchAndFieldCopy(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	tests := []struct {
		name         string
		oldType      common.AssetType
		newType      common.AssetType
		oldShape     string
		newShape     string
		oldName      string
		newName      string
		oldPrivLevel string
		oldZIndex    int64
		oldPos       *VertexClass
	}{
		{
			name:         "Process to Store",
			oldType:      common.AssetTypeApplication,
			newType:      common.AssetTypeDatabase,
			oldShape:     "process",
			newShape:     "store",
			oldName:      "Proc1",
			newName:      "Store1",
			oldPrivLevel: "admin",
			oldZIndex:    99,
			oldPos:       &VertexClass{X: 1, Y: 2},
		},
		{
			name:         "Store to Process",
			oldType:      common.AssetTypeDatabase,
			newType:      common.AssetTypeApplication,
			oldShape:     "store",
			newShape:     "process",
			oldName:      "Store2",
			newName:      "Proc2",
			oldPrivLevel: "user",
			oldZIndex:    42,
			oldPos:       &VertexClass{X: 3, Y: 4},
		},
		{
			name:         "Process to Process (only name change)",
			oldType:      common.AssetTypeApplication,
			newType:      common.AssetTypeApplication,
			oldShape:     "process",
			newShape:     "process",
			oldName:      "Proc3",
			newName:      "Proc3neu",
			oldPrivLevel: "guest",
			oldZIndex:    7,
			oldPos:       &VertexClass{X: 5, Y: 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldCell, err := tdo.generatePlacedCell(common.Asset{
				Type:        tt.oldType,
				ID:          "id1",
				DisplayName: tt.oldName,
			}, dontPlace{})
			require.NoError(t, err)
			oldCell.Data.PrivilegeLevel = stringPtr(tt.oldPrivLevel)
			oldCell.Data.Name = stringPtr(tt.oldName)
			oldCell.Position = tt.oldPos
			oldCell.ZIndex = tt.oldZIndex
			oldCell.Shape = tt.oldShape

			asset := common.Asset{
				Type:        tt.newType,
				ID:          "id1",
				DisplayName: tt.newName,
			}
			newCell, err := tdo.updateCell(*oldCell, asset)
			require.NoError(t, err)
			assert.Equal(t, tt.newName, *newCell.Data.Name)
			assert.Equal(t, tt.newName, newCell.Attrs.Text.Text)
			assert.Equal(t, tt.oldPrivLevel, *newCell.Data.PrivilegeLevel)
			assert.Equal(t, tt.oldZIndex, newCell.ZIndex)
			assert.Equal(t, tt.oldPos, newCell.Position)
			assert.Equal(t, tt.newShape, newCell.Shape)
		})
	}
}

// TestUpdateCell_Rename tests the updateCell function for renaming an existing cell
func TestUpdateCell_Rename(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	cell, err := tdo.generatePlacedCell(common.Asset{
		Type:        common.AssetTypeApplication,
		ID:          "id2",
		DisplayName: "OldName",
	}, dontPlace{})
	require.NoError(t, err)
	cell.Data.Name = stringPtr("OldName")
	asset := common.Asset{
		Type:        common.AssetTypeApplication,
		ID:          "id2",
		DisplayName: "NewName",
	}
	newCell, err := tdo.updateCell(*cell, asset)
	require.NoError(t, err)
	assert.Equal(t, "NewName", *newCell.Data.Name)
}

// TestUpdateCell_ErrorOnUnknownType tests the updateCell function for handling an unknown asset type
func TestUpdateCell_ErrorOnUnknownType(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	cell, err := tdo.generatePlacedCell(common.Asset{
		Type:        common.AssetTypeApplication,
		ID:          "id3",
		DisplayName: "Test",
	}, dontPlace{})
	require.NoError(t, err)
	asset := common.Asset{
		Type:        999999, // invalid Type
		ID:          "id3",
		DisplayName: "Test",
	}
	_, err = tdo.updateCell(*cell, asset)
	assert.Error(t, err)
}

// TestGenerateCell_ProcessAndStore tests the generateCell function for creating Process and Store cells
func TestGenerateCell_ProcessAndStore(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	cell, err := tdo.generatePlacedCell(common.Asset{
		Type:        common.AssetTypeApplication,
		ID:          "id5",
		DisplayName: "Proc5",
	}, dontPlace{})
	require.NoError(t, err)
	assert.Equal(t, "tm.Process", cell.Data.Type)
	assert.Equal(t, "Proc5", *cell.Data.Name)

	cell2, err := tdo.generatePlacedCell(common.Asset{
		Type:        common.AssetTypeDatabase,
		ID:          "id6",
		DisplayName: "Store6",
	}, dontPlace{})
	require.NoError(t, err)
	assert.Equal(t, "tm.Store", cell2.Data.Type)
	assert.Equal(t, "Store6", *cell2.Data.Name)
}

// TestGenerateCell_ErrorOnUnknownType tests the generateCell function for handling an unknown asset type
func TestGenerateCell_ErrorOnUnknownType(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	_, err := tdo.generatePlacedCell(common.Asset{
		Type:        999999,
		ID:          "id7",
		DisplayName: "Fail",
	}, dontPlace{})
	assert.Error(t, err)
}

// TestUpdateThreats tests the updateThreats function for updating threats
func TestUpdateThreats(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	// Case 31: no existing threats, asset has threats -> new threats created
	t.Run("none asset", func(t *testing.T) {
		asset := common.Asset{
			DisplayName: "A",
			Threats: []common.Threat{
				{ID: "t1", Title: "One", InternalID: generateIDHash("p", "t1"), IsGeneratedByUser: true, MapIndex: 0},
				{ID: "t2", Title: "Two", InternalID: generateIDHash("p", "t2"), IsGeneratedByUser: false, MapIndex: 1},
			},
			Extra: map[string]any{},
		}
		got := tdo.updateAssetThreats(asset)
		assert.NotNil(t, got, "expected not nil threats")
		assert.Len(t, *got, 2, "expected two new threats")
	})

	// Case 2: existing threats present and asset has corresponding (non-generated) threat -> update applied
	t.Run("existing asset update", func(t *testing.T) {
		id := "t-ex"
		internalID := generateIDHash("p", id)

		// existing model threat
		existing := Threat{
			ID:     id,
			Title:  "OldTitle",
			Number: Nullable[int64]{Value: 1, Set: true, Present: true},
			Score:  Nullable[string]{Value: "1.0", Set: true, Present: true},
		}

		asset := common.Asset{
			DisplayName: "A",
			Threats: []common.Threat{
				{ID: id, Title: "NewTitle", Status: common.Mitigated, InternalID: internalID, IsGeneratedByUser: false},
			},
			Extra: map[string]any{
				"ThreatModelMap": map[string]Threat{
					internalID: existing,
				},
			},
		}

		got := tdo.updateAssetThreats(asset)
		assert.NotNil(t, got, "expected not nil threats")
		assert.Len(t, *got, 1, "expected one updated threat")
		assert.Equal(t, "NewTitle", (*got)[0].Title, "threat title not updated")
	})
}

func TestGenerateCell_SetsThreatsAndDescription(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	asset := common.Asset{
		ID:          "asset-1",
		DisplayName: "MyAsset",
		Type:        common.AssetTypeApplication, // maps to tm.Process
		Threats: []common.Threat{
			{ID: "t1", Title: "One", Number: 1, Score: "1.0", InternalID: "iid-1", IsGeneratedByUser: true},
			{ID: "t2", Title: "Two", Number: 2, Score: "2.0", InternalID: "iid-2", IsGeneratedByUser: true},
		},
		Extra: map[string]any{},
	}

	cell, err := tdo.generatePlacedCell(asset, dontPlace{})
	require.NoError(t, err)

	// Data.Threats must be a non-nil pointer and contain the same number of threats
	if assert.NotNil(t, cell.Data.Threats, "expected Data.Threats to be non-nil") {
		assert.Equal(t, len(asset.Threats), len(*cell.Data.Threats), "unexpected number of threats in cell")
	}

	// Description should contain the analyzer ID tag for the asset ID
	expectedDesc := analyzerIDTag(asset.ID)
	if assert.NotNil(t, cell.Data.Description, "expected Data.Description to be set") {
		assert.Equal(t, expectedDesc, *cell.Data.Description, "unexpected description/analyzer tag")
	}
}

func TestUpdateCell_UsesUpdateThreatsResult(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	// prepare an existing cell (use defaultProcess to get a valid cell with tm.Process)
	cell := process("Name", "Description", false, nil, nil)

	// prepare asset with one existing threat (not generated by user) and one new (generated)
	// pick an internalID for lookup
	id := "tid"
	internalID := generateIDHash("somePath", id)

	// existing ThreatDragon threat stored in the model (value type is Threat from this package)
	existingModelThreat := Threat{
		ID:          id,
		Title:       "OldTitle",
		Status:      "open",
		Severity:    "low",
		Number:      Nullable[int64]{Value: 1, Set: true, Present: true},
		Score:       Nullable[string]{Value: "1.0", Set: true, Present: true},
		Description: analyzerIDTag(internalID),
	}

	// asset threats: one corresponds to existing (IsGeneratedByUser=false), one is newly created by user
	assetThreatExisting := common.Threat{
		ID:                id,
		Title:             "NewTitle",
		Status:            common.Mitigated,
		Severity:          "low",
		InternalID:        internalID,
		IsGeneratedByUser: false,
		Number:            1,
		Score:             "1.0",
	}

	assetThreatNew := common.Threat{
		ID:                "t-new",
		Title:             "BrandNew",
		InternalID:        "gen-1",
		IsGeneratedByUser: true,
		Number:            2,
		Score:             "2.0",
	}

	asset := common.Asset{
		DisplayName: "A",
		Type:        common.AssetTypeApplication,
		Threats:     []common.Threat{assetThreatExisting, assetThreatNew},
		Extra:       map[string]any{},
	}

	// prepare ThreatModelMap used by updateThreats: key is internalID -> existingModelThreat
	asset.Extra["ThreatModelMap"] = map[string]Threat{
		internalID: existingModelThreat,
	}

	// compute expected updated threats by calling updateThreats directly
	expected := tdo.updateAssetThreats(asset)

	// call updateCell and ensure it sets Data.Threats to the updateThreats result (content-wise)
	updatedCell, err := tdo.updateCell(cell, asset)
	require.NoError(t, err)

	// Data.Threats must be non-nil
	if assert.NotNil(t, updatedCell.Data.Threats, "expected Data.Threats to be non-nil after updateCell") {
		got := updatedCell.Data.Threats
		assert.NotNil(t, got, "expected not nil threats")
		// lengths must match
		assert.Equal(t, len(*expected), len(*got), "unexpected number of threats in updated cell")

		// compare elements' ID and Title to ensure update applied
		for i, threat := range *expected {
			assert.Equal(t, threat.ID, (*got)[i].ID, "mismatch ID at idx %d", i)
			assert.Equal(t, threat.Title, (*got)[i].Title, "mismatch Title at idx %d", i)
		}
	}
}

// TestGenerate_ThreatDefaultValuesNotPresent tests that when generating a cell from an asset with threats,
// if the Number and Score fields are not set, they remain nil in the output Threat structure.
func TestGenerate_ThreatDefaultValuesNotPresent(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	filepath := "somePath"
	id1 := "id-1"
	id2 := "id-2"
	tdo.threatMax = 2
	internalID1 := generateIDHash(filepath, id1)
	internalID2 := generateIDHash(filepath, id2)
	assetWithNilDefaults := common.Asset{
		ID:          "asset-1",
		DisplayName: "MyAsset",
		Type:        common.AssetTypeApplication, // maps to tm.Process
		Threats: []common.Threat{
			{ID: id1, Title: "One", InternalID: internalID1, IsGeneratedByUser: true, MapIndex: 0},                          // Number and Score are not set
			{ID: id2, Title: "Two", Number: 2, Score: "2.0", InternalID: internalID2, IsGeneratedByUser: true, MapIndex: 1}, // Number and Score are set
		},
		Extra: map[string]any{},
	}

	cell, err := tdo.generatePlacedCell(assetWithNilDefaults, dontPlace{})
	if !assert.NoError(t, err) {
		return
	}
	if !assert.NotNil(t, cell.Data.Threats, "expected Data.Threats to be non-nil") {
		return
	}

	threatMap := make(map[int]Threat)
	for idx, threat := range *cell.Data.Threats {
		threatMap[idx] = threat
	}
	// Check first threat (with default values)
	threat1, exists := threatMap[0]
	if assert.True(t, exists, "expected threatMap to contain: "+internalID1) {
		assert.Equal(t, true, threat1.Number.Present, "expected Number to be not present for threat: "+internalID1)
		assert.Equal(t, int64(3), threat1.Number.Value, "expected Number value to be 3 for threat: "+internalID1) //manipulated to be 3 due to threatMax increment
		assert.Equal(t, false, threat1.Score.Present, "expected Score to be not present for threat: "+internalID1)
	}

	// Check second threat (with set values)
	threat2, exists := threatMap[1]
	if assert.True(t, exists, "expected threatMap to contain: "+internalID2) {
		if assert.Equal(t, true, threat2.Number.Present, "expected Number to be present for threat: "+internalID2) {
			assert.Equal(t, int64(2), threat2.Number.Value, "unexpected Number value for threat: "+internalID2)
		}
		if assert.Equal(t, true, threat2.Score.Present, "expected Score to be present for threat: "+internalID2) {
			assert.Equal(t, "2.0", threat2.Score.Value, "unexpected Score value for threat: "+internalID2)
		}
	}
}

// TestGenerate_ExistingThreatsWithUnknownTypeOrModel tests existing threat dragon threats of type ThreatTypeUnkown or ModelTypeNotSupported are handled correctly and are outputted even if ignored by model merger
func TestGenerate_ExistingThreatsWithUnknownTypeOrModel(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	filepath := "somePath"
	id1 := "id-1"
	id2 := "id-2"
	id3 := "id-3"
	internalID3 := generateIDHash(filepath, id3)
	asset := common.Asset{
		ID:          "asset-1",
		DisplayName: "MyAsset",
		Type:        common.AssetTypeApplication, // maps to tm.Process
		Threats: []common.Threat{
			{ID: id3, Title: "Three", InternalID: internalID3, IsGeneratedByUser: true, MapIndex: 2, ModelType: common.STRIDE, Type: common.DenialOfService}, // normal threat
		},
		Extra: map[string]any{},
	}

	//Extra map needs to contain existing threats with unknown type/model for threatdragon threat
	threatExtraMap := make(map[int]Threat)

	//
	threatExtraMap[0] = Threat{
		ID:        id1,
		Type:      "xyz",    // unknown type
		ModelType: "STRIDE", // supported model
	}

	threatExtraMap[1] = Threat{
		ID:        id2,
		Type:      "Denial of service", // known type
		ModelType: "abc",               // not supported model
	}

	//normal threat
	threatExtraMap[2] = Threat{
		ID:        id3,
		Type:      "Denial of service",
		ModelType: "STRIDE",
	}

	asset.Extra["ThreatModelMap"] = threatExtraMap

	threats := tdo.updateAssetThreats(asset)

	assert.NotNil(t, threats, "expected not nil threats")
	assert.Equal(t, 3, len(*threats), "expected three threats")

}

// TestUpdateCell_SetsHasOpenThreats tests that the HasOpenThreats field is set correctly in updateCell
func TestUpdateCell_SetsHasOpenThreats(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	asset := common.Asset{
		ID:          "asset-1",
		DisplayName: "MyAsset",
		Type:        common.AssetTypeApplication, // maps to tm.Process
		Threats: []common.Threat{
			{ID: "t1", Title: "One", Status: common.Open, InternalID: "iid-1", IsGeneratedByUser: true},
			{ID: "t2", Title: "Two", Status: common.Mitigated, InternalID: "iid-2", IsGeneratedByUser: true},
		},
		Extra: map[string]any{},
	}

	cell, err := tdo.generatePlacedCell(asset, dontPlace{})
	assert.NoError(t, err)

	// Initially, HasOpenThreats should be true
	if assert.NotNil(t, cell.Data.Threats, "expected Data.Threats to be non-nil") {
		assert.Equal(t, true, cell.Data.HasOpenThreats, "expected HasOpenThreats to be true")
	}

	// Update asset to have all threats mitigated
	asset.Threats[0].Status = common.Mitigated

	updatedCell, err := tdo.updateCell(*cell, asset)
	assert.NoError(t, err)

	// Now, HasOpenThreats should be false
	if assert.NotNil(t, updatedCell.Data.Threats, "expected Data.Threats to be non-nil after update") {
		assert.Equal(t, false, updatedCell.Data.HasOpenThreats, "expected HasOpenThreats to be false after update")
	}
}

// TestGenerateCell_SetsHasOpenThreats tests that the HasOpenThreats field is set correctly in generatePlacedCell
func TestGenerateCell_SetsHasOpenThreats(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	asset1 := common.Asset{
		ID:          "asset-1",
		DisplayName: "MyAsset",
		Type:        common.AssetTypeApplication, // maps to tm.Process
		Threats: []common.Threat{
			{ID: "t1", Title: "One", Status: common.Mitigated, InternalID: "iid-1", IsGeneratedByUser: true},
			{ID: "t2", Title: "Two", Status: common.Mitigated, InternalID: "iid-2", IsGeneratedByUser: true},
		},
		Extra: map[string]any{},
	}

	cell, err := tdo.generatePlacedCell(asset1, dontPlace{})
	assert.NoError(t, err)

	// Since all threats are mitigated, HasOpenThreats should be false
	if assert.NotNil(t, cell.Data.Threats, "expected Data.Threats to be non-nil") {
		assert.Equal(t, false, cell.Data.HasOpenThreats, "expected HasOpenThreats to be false")
	}

	asset2 := common.Asset{
		ID:          "asset-2",
		DisplayName: "MyAsset",
		Type:        common.AssetTypeApplication, // maps to tm.Process
		Threats: []common.Threat{
			{ID: "t1", Title: "One", Status: common.Open, InternalID: "iid-1", IsGeneratedByUser: true},
			{ID: "t2", Title: "Two", Status: common.Mitigated, InternalID: "iid-2", IsGeneratedByUser: true},
		},
		Extra: map[string]any{},
	}

	cell2, err := tdo.generatePlacedCell(asset2, dontPlace{})
	assert.NoError(t, err)

	// Since all threats are mitigated, HasOpenThreats should be false
	if assert.NotNil(t, cell2.Data.Threats, "expected Data.Threats to be non-nil") {
		assert.Equal(t, true, cell2.Data.HasOpenThreats, "expected HasOpenThreats to be true")
	}
}

// Generate a test that evaluates if the ThreatTop is set correctly by the number of generated threats + threatTop of the model, this needs to be evaluated by the whole model
func TestGenerate_ThreatTopCalculation(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	model := common.EmptyThreatModel()
	model.Assets = []common.Asset{
		{
			ID:          "asset-1",
			DisplayName: "Asset 1",
			Type:        common.AssetTypeApplication,
			Threats: []common.Threat{
				{ID: "t1", Title: "One", InternalID: "iid-1", IsGeneratedByUser: false, MapIndex: 0},
				{ID: "t2", Title: "Two", InternalID: "iid-2", IsGeneratedByUser: false, MapIndex: 1},
			},
			Extra: map[string]any{},
		},
		{
			ID:          "asset-2",
			DisplayName: "Asset 2",
			Type:        common.AssetTypeDatabase,
			Threats: []common.Threat{
				{ID: "t3", Title: "Three", InternalID: "iid-3", IsGeneratedByUser: true, MapIndex: 2},
			},
			Extra: map[string]any{},
		},
	}

	err := tdo.Generate(&model)
	assert.NoError(t, err)

	//evaluate threattop
	expectedThreatTop := int64(3) // 2 threats from asset-1 + 1 threat from asset-2

	//add another asset with generated threats to see if threattop increases
	model.Assets = append(model.Assets, common.Asset{
		ID:          "asset-3",
		DisplayName: "Asset 3",
		Type:        common.AssetTypeInfrastructure,
		Threats: []common.Threat{
			{ID: "t4", Title: "Four", InternalID: "iid-4", IsGeneratedByUser: true, MapIndex: 3},
			{ID: "t5", Title: "Five", InternalID: "iid-5", IsGeneratedByUser: true, MapIndex: 4},
			{ID: "t6", Title: "Six", InternalID: "iid-6", IsGeneratedByUser: true, MapIndex: 5},
		},
		Extra: map[string]any{},
	})

	err = tdo.Generate(&model)
	assert.NoError(t, err)

	expectedThreatTop += int64(3) // 3 threats from asset-3

	assert.Equal(t, expectedThreatTop, tdo.threatMax, "threatTop not calculated correctly")
}

// TestGenerateDataFlowsForNewModel tests that data flows are generated correctly for a new model
func TestGenerateDataFlowsForNewModel(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/ouput/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	model := common.EmptyThreatModel()
	internalID1 := generateIDHash("somePath", "id-1")
	internalID2 := generateIDHash("somePath", "id-2")

	model.Assets = []common.Asset{
		{DisplayName: "App1",
			ID:   internalID1,
			Type: common.AssetTypeApplication},
		{DisplayName: "DB1",
			ID:   internalID2,
			Type: common.AssetTypeDatabase},
	}
	model.DataFlows = []common.DataFlow{
		{
			Name:          "DF1",
			SourceID:      internalID1,
			TargetID:      internalID2,
			Bidirectional: true,
		},
	}

	project, err := tdo.generateNewModel(&model)
	assert.NoError(t, err)
	assert.NotNil(t, project)
	assert.NotEmpty(t, project.Detail.Diagrams)
	// count flow cells in diagram
	flowCount := 0
	for _, c := range project.Detail.Diagrams[0].Cells {
		if c.Shape == "flow" {
			flowCount++
		}
	}
	assert.Equal(t, len(model.DataFlows), flowCount, "expected number of generated dataflow cells to match model.DataFlows")
}

// TestGenerateDataFlowsForUpdatedModel tests that data flows are preserved/handled correctly when updating an existing model
func TestGenerateDataFlowsForUpdatedModel(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/ouput/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	// prepare existing ThreatDragon project with two assets and two dataflows between them
	filepath := "somePath"
	internalID1 := generateIDHash(filepath, "id-1")
	internalID2 := generateIDHash(filepath, "id-2")

	// create placed asset cells (process/store)
	cell1 := process("App1", analyzerIDTag(internalID1), false, nil, nil)
	cell2 := store("DB1", analyzerIDTag(internalID2), nil, nil)

	// create two dataflow cells connecting the above cells
	flow1 := tdo.newConnectedDataflow("DF1", analyzerIDTag("df1"), "", false, false, &cell1, &cell2, true, nil)
	flow2 := tdo.newConnectedDataflow("DF2", analyzerIDTag("df2"), "", false, false, &cell2, &cell1, false, nil)
	flow3 := tdo.newSourceDataflow("DFS1", analyzerIDTag("dfs1"), "", false, false, &cell1, false, nil)
	flow4 := tdo.newTargetDataflow("DFT1", analyzerIDTag("dft1"), "", false, false, &cell1, false, nil)
	existingTD := Project{
		Detail: Detail{
			Diagrams: []Diagram{
				{
					ID:    0,
					Title: "existing",
					Cells: []Cell{
						cell1,
						cell2,
						flow1,
						flow2,
						flow3,
						flow4,
					},
				},
			},
		},
	}

	// prepare model where assets map to existing diagram cell indices so updateExistingModel will update them
	model := common.EmptyThreatModel()
	model.Assets = []common.Asset{
		{
			ID:          internalID1,
			DisplayName: "App1",
			Type:        common.AssetTypeApplication,
			Extra: map[string]any{
				"ThreatDragonDiagramCellIdx": "0-0",
			},
		},
		{
			ID:          internalID2,
			DisplayName: "DB1",
			Type:        common.AssetTypeDatabase,
			Extra: map[string]any{
				"ThreatDragonDiagramCellIdx": "0-1",
			},
		},
	}

	// Add DataFlows that map to the existing flow cell indices in the diagram
	model.DataFlows = []common.DataFlow{
		{
			ID:       "df1",
			Name:     "DF1",
			SourceID: internalID1,
			TargetID: internalID2,
			Extra: map[string]any{
				"ThreatDragonDiagramCellIdx": "0-2", // flows are at indices 2 and 3 in existingTD
			},
		},
		{
			ID:       "df2",
			Name:     "DF2",
			SourceID: internalID2,
			TargetID: internalID1,
			Extra: map[string]any{
				"ThreatDragonDiagramCellIdx": "0-3",
			},
		},
		{
			ID:       "dfs1",
			Name:     "DFS1",
			SourceID: internalID2,
			TargetID: internalID1,
			Extra: map[string]any{
				"ThreatDragonDiagramCellIdx": "0-4",
			},
		},
		{
			ID:       "dft1",
			Name:     "DFt1",
			SourceID: internalID2,
			TargetID: internalID1,
			Extra: map[string]any{
				"ThreatDragonDiagramCellIdx": "0-5",
			},
		},
	}

	updatedProject, err := tdo.updateExistingModel(&model, existingTD)
	assert.NoError(t, err)
	assert.NotNil(t, updatedProject)
	assert.NotEmpty(t, updatedProject.Detail.Diagrams)

	// ensure the existing flow cells are still present after update
	flowCount := 0
	for _, c := range updatedProject.Detail.Diagrams[0].Cells {
		if c.Shape == "flow" {
			flowCount++
		}
	}
	assert.Equal(t, 4, flowCount, "expected the two existing dataflow cells to be preserved after update")
}

// TestGetThreatFrequency tests the getThreatFrequency function
func TestGetThreatFrequency(t *testing.T) {
	tests := []struct {
		name               string
		threats            *[]Threat
		oldThreatFrequency *ThreatFrequency
		expected           *ThreatFrequency
	}{
		{
			name: "Stride frequency",
			threats: &[]Threat{
				{Type: common.Spoofing.String()},
				{Type: common.DenialOfService.String()},
				{Type: common.DenialOfService.String()},
				{Type: common.ElevationOfPrivilege.String()},
			},
			oldThreatFrequency: nil,
			expected: &ThreatFrequency{
				Spoofing:              int64Ptr(1),
				DenialOfService:       int64Ptr(2),
				ElevationOfPrivilege:  int64Ptr(1),
				InformationDisclosure: int64Ptr(0),
				Repudiation:           int64Ptr(0),
				Tampering:             int64Ptr(0),
			},
		},
		{
			name: "Stride frequency with unkown types",
			threats: &[]Threat{
				{Type: "Availability"},
				{Type: common.DenialOfService.String()},
				{Type: common.DenialOfService.String()},
				{Type: common.ElevationOfPrivilege.String()},
			},
			oldThreatFrequency: nil,
			expected: &ThreatFrequency{
				Spoofing:              int64Ptr(0),
				DenialOfService:       int64Ptr(2),
				ElevationOfPrivilege:  int64Ptr(1),
				InformationDisclosure: int64Ptr(0),
				Repudiation:           int64Ptr(0),
				Tampering:             int64Ptr(0),
			},
		},
		{
			name: "Stride frequency with unkown types and no old frequency",
			threats: &[]Threat{
				{Type: "Availability"},
				{Type: "Availability"},
				{Type: "Integrity"},
			},
			oldThreatFrequency: nil,
			expected: &ThreatFrequency{
				Spoofing:              int64Ptr(0),
				DenialOfService:       int64Ptr(0),
				ElevationOfPrivilege:  int64Ptr(0),
				InformationDisclosure: int64Ptr(0),
				Repudiation:           int64Ptr(0),
				Tampering:             int64Ptr(0),
			},
		},
		{
			name: "Stride frequency with both types and old frequency",
			threats: &[]Threat{
				{Type: "Availability"},
				{Type: "Availability"},
				{Type: "Integrity"},
				{Type: common.Spoofing.String()},
			},
			oldThreatFrequency: &ThreatFrequency{
				Availability:    int64Ptr(2),
				Confidentiality: int64Ptr(2),
			},
			expected: &ThreatFrequency{
				Availability:    int64Ptr(2),
				Confidentiality: int64Ptr(2),
				Spoofing:        int64Ptr(1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getThreatFrequency(tt.threats, tt.oldThreatFrequency)

			if tt.expected == nil {
				assert.Nil(t, result)
				return
			} else if result == nil {
				assert.Fail(t, "result is nil but expected is not")
				return
			} else {
				// compare each field individually
				if tt.expected.Spoofing != nil {
					assert.Equal(t, *tt.expected.Spoofing, *result.Spoofing, "Spoofing mismatch")
				}
				if tt.expected.DenialOfService != nil {
					assert.Equal(t, *tt.expected.DenialOfService, *result.DenialOfService, "DenialOfService mismatch")
				}
				if tt.expected.ElevationOfPrivilege != nil {
					assert.Equal(t, *tt.expected.ElevationOfPrivilege, *result.ElevationOfPrivilege, "ElevationOfPrivilege mismatch")
				}
				if tt.expected.InformationDisclosure != nil {
					assert.Equal(t, *tt.expected.InformationDisclosure, *result.InformationDisclosure, "InformationDisclosure mismatch")
				}
				if tt.expected.Repudiation != nil {
					assert.Equal(t, *tt.expected.Repudiation, *result.Repudiation, "Repudiation mismatch")
				}
				if tt.expected.Tampering != nil {
					assert.Equal(t, *tt.expected.Tampering, *result.Tampering, "Tampering mismatch")
				}

				if tt.expected.Availability != nil {
					assert.NotNil(t, result.Availability)
					assert.Equal(t, *tt.expected.Availability, *result.Availability, "Availability mismatch")
				}

				if tt.expected.Confidentiality != nil {
					assert.NotNil(t, result.Confidentiality)
					assert.Equal(t, *tt.expected.Confidentiality, *result.Confidentiality, "Confidentiality mismatch")
				}
				assert.Nil(t, result.Integrity, "Integrity should not be set due to not given in frequency calculation")

			}
		})
	}
}
