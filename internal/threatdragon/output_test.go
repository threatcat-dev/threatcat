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

	cs := NewCoordinateSystem(slog.Default())
	cells, err := tdo.generateNewCells([]common.Asset{}, cs)
	require.NoError(t, err)

	assert.Equal(t, emptyCells, cells)
}

func TestGenerateCellsWithOneAsset(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())
	cs := NewCoordinateSystem(slog.Default())
	cells, err := tdo.generateNewCells([]common.Asset{{Type: common.AssetTypeDatabase}}, cs)
	require.NoError(t, err)

	assert.Equal(t, 1, len(cells))
}

func TestGenerateCellsWithMultipleAsset(t *testing.T) {
	tdo := NewThreatdragonOutput("testdata/testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	assets := []common.Asset{
		{Type: common.AssetTypeDatabase},
		{Type: common.AssetTypeApplication},
		{Type: common.AssetTypeUnknown},
		{Type: common.AssetTypeInfrastructure},
	}

	cs := NewCoordinateSystem(slog.Default())
	cells, err := tdo.generateNewCells(assets, cs)
	require.NoError(t, err)

	assert.Equal(t, len(assets), len(cells))
}
