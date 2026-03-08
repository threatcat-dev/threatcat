package threatdragon

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// removeThreatFrequency removes all ThreatFrequency fields from the JSON structure
func removeThreatFrequency(data []byte) ([]byte, error) {
	var project Project
	if err := json.Unmarshal(data, &project); err != nil {
		return nil, err
	}

	// Remove ThreatFrequency from all cells in all diagrams
	for i := range project.Detail.Diagrams {
		for j := range project.Detail.Diagrams[i].Cells {
			project.Detail.Diagrams[i].Cells[j].Data.ThreatFrequency = nil
		}
	}

	return json.Marshal(project)
}

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
			originalContent, err := os.ReadFile(demoModelPath)
			require.NoError(t, err, "failed to read original ThreatDragon JSON")

			outputContent, err := os.ReadFile(outputPath)
			require.NoError(t, err, "failed to read output ThreatDragon JSON")

			// Remove ThreatFrequency fields before comparison due to corrupted Threat frequency in test data (is checked by other tests)
			normalizedOriginal, err := removeThreatFrequency(originalContent)
			require.NoError(t, err, "failed to normalize original JSON")

			normalizedOutput, err := removeThreatFrequency(outputContent)
			require.NoError(t, err, "failed to normalize output JSON")

			assert.JSONEq(t, string(normalizedOriginal), string(normalizedOutput), "The original and output ThreatDragon JSON files do not match")
		})
	}
}
