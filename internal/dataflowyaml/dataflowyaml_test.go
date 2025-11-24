package dataflowyaml

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataflowYamlParser(t *testing.T) {
	const filePath = "testdata/data-flow-for-test.yml"

	parser := NewDataflowYamlParser(filePath, slog.Default())
	tModel, err := parser.ParseAndConvert()
	require.NoError(t, err)

	dataFlows := tModel.DataFlows

	assert.Equal(t, nil, err)
	assert.Equal(t, 2, len(dataFlows))
	assert.Equal(t, "web", dataFlows[0].Source)
	assert.Equal(t, "db", dataFlows[0].Target)
	assert.Equal(t, "Flow1", dataFlows[0].Name)
	assert.Equal(t, "http", dataFlows[0].Protocol)
	assert.Equal(t, false, dataFlows[0].Encrypted)
	assert.Equal(t, true, dataFlows[0].PublicNetwork)
	assert.Equal(t, false, dataFlows[0].Bidirectional)

	assert.Equal(t, "web", dataFlows[1].Source)
	assert.Equal(t, "db2", dataFlows[1].Target)
	assert.Equal(t, "Flow12", dataFlows[1].Name)
	assert.Equal(t, "https", dataFlows[1].Protocol)
	assert.Equal(t, true, dataFlows[1].Encrypted)
	assert.Equal(t, false, dataFlows[1].PublicNetwork)
	assert.Equal(t, true, dataFlows[1].Bidirectional)

}
