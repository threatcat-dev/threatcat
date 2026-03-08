package dataflow

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// TestReplaceTargetAndSourceIDs tests the replacement of target and source with hashed IDs
func TestGenerateTargetAndSourceIDs(t *testing.T) {
	dfs := []common.DataFlow{
		{
			Source: "service1",
			Target: "service2",
		},
		{
			Source: "service2",
			Target: "service3",
		},
	}

	id1 := common.GenerateIDHashFromFilePath("path/to/docker-compose.yml", "service1")
	id2 := common.GenerateIDHashFromFilePath("path/to/docker-compose.yml", "service2")
	id3 := common.GenerateIDHashFromFilePath("path/to/docker-compose.yml", "service3")
	assets := []common.Asset{
		{
			ID:          id1,
			Type:        common.AssetTypeApplication,
			DisplayName: "service1",
		},
		{
			ID:          id2,
			Type:        common.AssetTypeDatabase,
			DisplayName: "service2",
		},
		{
			ID:          id3,
			Type:        common.AssetTypeWebserver,
			DisplayName: "service3",
		},
	}

	ReplaceAssetNamesWithIDs(dfs, assets, slog.Default())

	assert.Equal(t, id1, dfs[0].SourceID)
	assert.Equal(t, id2, dfs[0].TargetID)
	assert.Equal(t, id2, dfs[1].SourceID)
	assert.Equal(t, id3, dfs[1].TargetID)
}
