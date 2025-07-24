package updatability

import (
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatcat-dev/threatcat/internal/common"
	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/modelmerger"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

type dummyChangelog struct{}

func (dc dummyChangelog) AddEntry(string) {}

// TestUpdateWorkflow tests the updatability of the threat model
// by replacing the docker-compose file with an updated version and regenerating the ThreatDragon output.
func TestUpdateWorkflowAddAssets(t *testing.T) {
	const (
		initialComposeFile = "./input1.docker-compose.yml"
		updatedComposeFile = "./input2.docker-compose.yml"
		tempComposeFile    = "./temp_3_containers.docker-compose.yml"
		outputPath         = "./testoutput_updatable_threatdragon.json"
	)

	defer os.Remove(tempComposeFile)

	// Step 1: Initialize with initial docker-compose file
	setupComposeFile(t, initialComposeFile, tempComposeFile)
	initialAssets := parseAndAnalyzeCompose(t, tempComposeFile)

	output := threatdragon.NewThreatdragonOutput(outputPath, dummyChangelog{}, slog.Default())
	require.NoError(t, output.Generate(initialAssets), "failed to generate initial ThreatDragon output")

	// Step 2: Replace with updated docker-compose file
	setupComposeFile(t, updatedComposeFile, tempComposeFile)
	updatedAssets := parseAndAnalyzeCompose(t, tempComposeFile)

	// Step 3: Parse and analyze ThreatDragon output
	tdAssets := parseAndAnalyzeThreatDragon(t, outputPath)

	// Step 4: Merge and regenerate
	merger := modelmerger.NewModelMerger(dummyChangelog{}, slog.Default())
	merged := merger.Merge([]common.ThreatModel{*updatedAssets, *tdAssets})

	require.NoError(t, output.Generate(&merged), "failed to regenerate ThreatDragon output with merged model")
	assert.Len(t, merged.Assets, 4, "expected 4 assets in the merged model")
}

func TestUpdateWorkflowRemoveAssets(t *testing.T) {
	const (
		initialComposeFile = "./input2.docker-compose.yml"
		updatedComposeFile = "./input1.docker-compose.yml"
		tempComposeFile    = "./temp_3_containers.docker-compose.yml"
		outputPath         = "./testoutput_updatable_threatdragon.json"
	)

	defer os.Remove(tempComposeFile)

	// Step 1: Initialize with initial docker-compose file
	setupComposeFile(t, initialComposeFile, tempComposeFile)
	initialAssets := parseAndAnalyzeCompose(t, tempComposeFile)

	output := threatdragon.NewThreatdragonOutput(outputPath, dummyChangelog{}, slog.Default())
	require.NoError(t, output.Generate(initialAssets), "failed to generate initial ThreatDragon output")

	// Step 2: Replace with updated docker-compose file
	setupComposeFile(t, updatedComposeFile, tempComposeFile)
	updatedAssets := parseAndAnalyzeCompose(t, tempComposeFile)

	// Step 3: Parse and analyze ThreatDragon output
	tdAssets := parseAndAnalyzeThreatDragon(t, outputPath)

	// Step 4: Merge and regenerate
	merger := modelmerger.NewModelMerger(dummyChangelog{}, slog.Default())
	merged := merger.Merge([]common.ThreatModel{*updatedAssets, *tdAssets})

	require.NoError(t, output.Generate(&merged), "failed to regenerate ThreatDragon output with merged model")
	assert.Len(t, merged.Assets, 3, "expected 3 assets in the merged model")
}

func TestUpdateWorkflowOnThreatDragon(t *testing.T) {
	const (
		initialComposeFile = "./input2.docker-compose.yml"
		updatedComposeFile = "./input1.docker-compose.yml"
		tempComposeFile    = "./temp_3_containers.docker-compose.yml"
		initailTDModel     = "./model_with_user_created_process.json"
		outputPath         = "./testoutput_updatable_threatdragon.json"
	)
	defer os.Remove(tempComposeFile)

	// Step 1: Update the inital Threatdragon model with the docker compose with 4 elements
	setupComposeFile(t, initialComposeFile, tempComposeFile)
	initialAssets := parseAndAnalyzeCompose(t, tempComposeFile)
	tdAssets := parseAndAnalyzeThreatDragon(t, initailTDModel)

	merger := modelmerger.NewModelMerger(dummyChangelog{}, slog.Default())
	merged := merger.Merge([]common.ThreatModel{*initialAssets, *tdAssets})

	output := threatdragon.NewThreatdragonOutput(outputPath, dummyChangelog{}, slog.Default())
	require.NoError(t, output.Generate(&merged), "failed to generate initial ThreatDragon output")

	// Step 2: Parse and analyze ThreatDragon output and check if it was updated correctly
	tdAssets = parseAndAnalyzeThreatDragon(t, outputPath)

	threatdragonFromExtra, ok := tdAssets.Extra["ThreatDragonModel"]
	assert.True(t, ok, "failed to retrive ThreatDragonModel from first input")
	project, ok := threatdragonFromExtra.(threatdragon.Project)
	assert.True(t, ok, "failed to cast input to ThreatDragonModel from first input")

	cells := project.Detail.Diagrams[0].Cells
	// after the update there should be 5 elements. The user_created_process was created by the user
	// the other elements are from the docker compose
	assert.Len(t, cells, 5, "expected 5 cells in the threatdragon model")
	assert.True(t, hasCellWithName(cells, "user_created_process"), "failed to find user_created_process")
	assert.True(t, hasCellWithName(cells, "web"), "failed to find web")
	assert.True(t, hasCellWithName(cells, "web2"), "failed to find web2")
	assert.True(t, hasCellWithName(cells, "db"), "failed to find db")
	assert.True(t, hasCellWithName(cells, "db2"), "failed to find db2")

	// Step 3: Replace with updated docker-compose file with 3 elements and merge and generated updated Threatdragon model
	setupComposeFile(t, updatedComposeFile, tempComposeFile)
	updatedAssets := parseAndAnalyzeCompose(t, tempComposeFile)
	merged = merger.Merge([]common.ThreatModel{*updatedAssets, *tdAssets})

	require.NoError(t, output.Generate(&merged), "failed to regenerate ThreatDragon output with merged model")

	// Step 4: Parse and analyze ThreatDragon output and check if it was updated correctly
	tdAssets = parseAndAnalyzeThreatDragon(t, outputPath)

	threatdragonFromExtra, ok = tdAssets.Extra["ThreatDragonModel"]
	assert.True(t, ok, "failed to retrive ThreatDragonModel from second input")
	project, ok = threatdragonFromExtra.(threatdragon.Project)
	assert.True(t, ok, "failed to cast input to ThreatDragonModel from second input")

	cells = project.Detail.Diagrams[0].Cells
	// after the update there should be 4 elements. The user_created_process was created by the user
	// the other elements are from the docker compose. web2 should be removed
	assert.Len(t, cells, 4, "expected 4 cells in the threatdragon model")
	assert.True(t, hasCellWithName(cells, "user_created_process"), "failed to find user_created_process")
	assert.True(t, hasCellWithName(cells, "web"), "failed to find web")
	assert.True(t, hasCellWithName(cells, "db"), "failed to find db")
	assert.True(t, hasCellWithName(cells, "db2"), "failed to find db2")
}

func hasCellWithName(cells []threatdragon.Cell, name string) bool {
	return slices.ContainsFunc(cells, func(cell threatdragon.Cell) bool {
		return *cell.Data.Name == name
	})
}

// setupComposeFile sets up the docker-compose file for testing by creating a hard link to the source file.
// This allows for easy swapping of the docker-compose file while keeping the same file name.
func setupComposeFile(t *testing.T, src, dst string) {
	t.Helper()
	_ = os.Remove(dst)
	err := os.Link(src, dst)
	require.NoError(t, err, "failed to set up docker-compose file")
}

// parseAndAnalyzeCompose parses and analyzes a docker-compose file and returns the threat model.
func parseAndAnalyzeCompose(t *testing.T, path string) *common.ThreatModel {
	t.Helper()
	dockerImageMap, err := dockercompose.NewDockerImageMap("")
	require.NoError(t, err, "failed to create DockerImageMap")

	parser := dockercompose.NewDockerComposeParser(path, slog.Default())
	analyzer := dockercompose.NewDockerComposeAnalyzer(path, slog.Default())

	parsed, err := parser.ParseDockerComposeYML()
	require.NoError(t, err, "failed to parse docker-compose")

	assets, err := analyzer.Analyze(parsed, dockerImageMap)
	require.NoError(t, err, "failed to analyze docker-compose")

	return assets
}

// parseAndAnalyzeThreatDragon parses and analyzes a ThreatDragon file and returns the threat model.
func parseAndAnalyzeThreatDragon(t *testing.T, path string) *common.ThreatModel {
	t.Helper()
	input := threatdragon.NewThreatDragonInput(path, slog.Default())

	analyzed, err := input.Analyze()
	require.NoError(t, err, "failed to analyze ThreatDragon model")

	return analyzed
}
