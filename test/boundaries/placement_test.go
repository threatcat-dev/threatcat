package boundaries

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatcat-dev/threatcat/internal/common"
	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

type dummyChangelog struct{}

func (dc dummyChangelog) AddEntry(string) {}

// TestFreshGenerationAssetsInsideBoundaries verifies that after a fresh ThreatDragon
// generation the pixel positions of all asset cells are inside the rectangles of the
// trust boundaries they belong to.
//
// The check works by round-tripping the output through ThreatDragonInput: the input
// analyzer re-derives trust-boundary membership purely from pixel positions
// (linkAssetsWithTrustboundaries). If the positions are correct, those memberships
// must match the ones the docker-compose analyzer originally computed.
func TestFreshGenerationAssetsInsideBoundaries(t *testing.T) {
	const (
		composeFile = "./input.docker-compose.yaml"
		outputPath  = "./testoutput_placement.json"
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

func findBoundary(boundaries []common.TrustBoundary, id string) *common.TrustBoundary {
	for i := range boundaries {
		if boundaries[i].ID == id {
			return &boundaries[i]
		}
	}
	return nil
}
