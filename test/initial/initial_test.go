package initial

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

type dummyChangelog struct{}

func (dc dummyChangelog) AddEntry(string) {}

// TestSimpleWorkflow is a simple smoke test for the initial threat model generation from a docker-compose file.
// It parses the docker-compose file, analyzes it, and generates a ThreatDragon output file.
// The results are not compared to any expected output, but the test ensures that no errors occur during the process.
func TestSimpleWorkflow(t *testing.T) {
	const dockerComposePath = "./input.docker-compose.yml"

	dockerImageMap, err := dockercompose.NewDockerImageMap("")
	require.NoError(t, err)

	parser := dockercompose.NewDockerComposeParser(dockerComposePath, slog.Default())
	analyzer := dockercompose.NewDockerComposeAnalyzer(dockerComposePath, slog.Default())

	parsed, err := parser.ParseDockerComposeYML()
	require.NoError(t, err)

	assets, err := analyzer.Analyze(parsed, dockerImageMap)
	require.NoError(t, err)

	output := threatdragon.NewThreatdragonOutput("./testoutput_threatdragon.json", dummyChangelog{}, slog.Default())

	err = output.Generate(assets)
	require.NoError(t, err)
}
