package boundaries

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

// TestComplexGenerationAssetsInsideBoundaries verifies that after a fresh ThreatDragon
// generation from the complex docker-compose file the pixel positions of all asset cells
// are inside the rectangles of the trust boundaries they belong to.
//
// The complex compose file contains five networks (frontend, backend, database, messaging,
// monitoring) with services spread across multiple networks, making it a richer test case
// for the placement solver.
func TestComplexGenerationAssetsInsideBoundaries(t *testing.T) {
	const (
		composeFile = "./complex.docker-compose.yaml"
		outputPath  = "./testoutput_complex_placement.json"
	)
	defer os.Remove(outputPath)

	// Step 1: derive expected memberships from the docker-compose file.
	dockerImageMap, err := dockercompose.NewDockerImageMap("")
	require.NoError(t, err)

	parser := dockercompose.NewDockerComposeParser(composeFile, slog.Default())
	analyzer := dockercompose.NewDockerComposeAnalyzer(composeFile, slog.Default())

	parsed, err := parser.ParseDockerComposeYML()
	require.NoError(t, err)

	initialModel, err := analyzer.Analyze(parsed, dockerImageMap)
	require.NoError(t, err)

	// Step 2: generate a ThreatDragon file from the initial model.
	output := threatdragon.NewThreatdragonOutput(outputPath, dummyChangelog{}, slog.Default())
	require.NoError(t, output.Generate(initialModel))

	// Step 3: re-parse the generated file; the input analyzer infers membership
	// by testing whether each asset rectangle lies inside a boundary rectangle.
	tdInput := threatdragon.NewThreatDragonInput(outputPath, slog.Default())
	reparsedModel, err := tdInput.Analyze()
	require.NoError(t, err)

	// Step 4: for every boundary the docker-compose analyzer declared, the set of
	// contained assets derived from pixel positions must match exactly.
	require.NotEmpty(t, initialModel.Boundaries, "expected at least one trust boundary from docker-compose")

	for _, boundary := range initialModel.Boundaries {
		reparsedBoundary := findBoundary(reparsedModel.Boundaries, boundary.ID)
		require.NotNil(t, reparsedBoundary,
			"boundary %q (id %s) not found in re-parsed output", boundary.DisplayName, boundary.ID)

		assert.ElementsMatch(t, boundary.ContainedAssets, reparsedBoundary.ContainedAssets,
			"boundary %q: assets inside the boundary rectangle do not match the expected assets;\n"+
				"this means one or more assets were generated outside the boundary's pixel rectangle",
			boundary.DisplayName)
	}
}
