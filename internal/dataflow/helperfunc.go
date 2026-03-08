package dataflow

import (
	"log/slog"

	"github.com/threatcat-dev/threatcat/internal/common"
)

// ReplaceAssetNamesWithIDs replaces asset DisplayNames with their IDs in the given dataflows.
func ReplaceAssetNamesWithIDs(dataflows []common.DataFlow, assets []common.Asset, logger *slog.Logger) {
	assetsByName := make(map[string]string, len(assets))
	for _, asset := range assets {
		assetsByName[asset.DisplayName] = asset.ID
	}

	for i := range dataflows {
		if id, ok := assetsByName[dataflows[i].Source]; ok {
			logger.Debug("Found Source for asset", "asset", dataflows[i].Source, "id", id)
			dataflows[i].SourceID = id
		} else if dataflows[i].SourceID != "" {
			logger.Warn("No matching asset found", "source", dataflows[i].Source)
		}
		if id, ok := assetsByName[dataflows[i].Target]; ok {
			logger.Debug("Found Source for asset", "asset", dataflows[i].Target, "id", id)
			dataflows[i].TargetID = id
		} else if dataflows[i].TargetID != "" {
			logger.Warn("No matching asset found", "target", dataflows[i].Target)
		}
	}
}
