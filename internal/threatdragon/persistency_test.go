package threatdragon

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestThreatdragonPersistency tests the persistency of ThreatDragon data
// by parsing, analyzing and then outputting the demo model and comparing it to the original model.
// It ensures that the data remains consistent and unchanged throughout the process.
func TestThreatdragonPersistency(t *testing.T) {
	demoModels, err := os.ReadDir("testdata/models")
	require.NoError(t, err, "failed to read testdata/models directory")
	for _, model := range demoModels {
		// Skip the LICENSE and NOTICE files
		if strings.Contains(model.Name(), ".txt") {
			continue
		}

		t.Run(model.Name(), func(t *testing.T) {
			// Read the demo model file
			demoModelPath := "testdata/models/" + model.Name()
			outputPath := "testdata/output/testoutput_" + model.Name()

			input := NewThreatDragonInput(demoModelPath, slog.Default())
			analyzed, err := input.Analyze()
			require.NoError(t, err, "failed to analyze ThreatDragon JSON")

			output := NewThreatdragonOutput(outputPath, dummyChangelog{}, slog.Default())

			err = output.Generate(analyzed)
			require.NoError(t, err, "failed to generate ThreatDragon output")

			// Compare the original and output files
			orinalContent, err := os.ReadFile(demoModelPath)
			require.NoError(t, err, "failed to read original ThreatDragon JSON")

			outputContent, err := os.ReadFile(outputPath)
			require.NoError(t, err, "failed to read output ThreatDragon JSON")

			assert.JSONEq(t, string(orinalContent), string(outputContent), "The original and output ThreatDragon JSON files do not match")
		})
	}
}
