package threatdragon

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModel tests the ThreatDragon model by reading demo models from the testdata directory,
// unmarshalling them into a Project struct, and then marshalling them back to JSON.
// It ensures that the original and output JSON data are equivalent, verifying the integrity of the model.
func TestModel(t *testing.T) {
	// Get all demo models from the testdata directory
	demoModels, err := os.ReadDir("testdata/models")
	require.NoError(t, err, "failed to read testdata/models directory")
	for _, model := range demoModels {
		// Skip the LICENSE and NOTICE files
		if strings.Contains(model.Name(), ".txt") {
			continue
		}

		t.Run(model.Name(), func(t *testing.T) {
			// Read the demo model file
			modelPath := "testdata/models/" + model.Name()
			modelFile, err := os.ReadFile(modelPath)
			require.NoError(t, err, "failed to read demo model file")

			// Unmarshal the JSON data into a Project struct
			var tdModel Project
			err = json.Unmarshal(modelFile, &tdModel)
			require.NoError(t, err, "failed to unmarshal demo model JSON")

			// Marshal the Project struct back to JSON
			output, err := json.MarshalIndent(tdModel, "", "    ")
			require.NoError(t, err, "failed to marshal demo model JSON")

			// Compare the original and output JSON
			assert.JSONEq(t, string(modelFile), string(output), "demo model JSON does not match original")
		})
	}
}

// TestNullableString_RoundTrip tests the round-trip conversion of Nullable[string] in JSON.
// It checks various cases including missing keys, null values, empty strings, and non-empty strings.
func TestNullableString_RoundTrip(t *testing.T) {
	type Payload struct {
		Name Nullable[string] `json:"name,omitzero"`
	}

	tests := []struct {
		name            string
		inputJSON       string
		expectedSet     bool
		expectedPresent bool
		expectedValue   string
	}{
		{
			name:            "missing key",
			inputJSON:       `{}`,
			expectedSet:     false,
			expectedPresent: false,
			expectedValue:   "",
		},
		{
			name:            "null value",
			inputJSON:       `{"name":null}`,
			expectedSet:     true,
			expectedPresent: false,
			expectedValue:   "",
		},
		{
			name:            "empty string",
			inputJSON:       `{"name":""}`,
			expectedSet:     true,
			expectedPresent: true,
			expectedValue:   "",
		},
		{
			name:            "non-empty string",
			inputJSON:       `{"name":"Alice"}`,
			expectedSet:     true,
			expectedPresent: true,
			expectedValue:   "Alice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var payload Payload

			// Unmarshal input JSON
			err := json.Unmarshal([]byte(tc.inputJSON), &payload)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedSet, payload.Name.Set)
			assert.Equal(t, tc.expectedPresent, payload.Name.Present)
			assert.Equal(t, tc.expectedValue, payload.Name.Value)

			// Marshal back to JSON
			outputJSON, err := json.Marshal(payload)
			require.NoError(t, err)

			// Compare input and output JSON (they should be equivalent)
			assert.JSONEq(t, tc.inputJSON, string(outputJSON))
		})
	}
}
