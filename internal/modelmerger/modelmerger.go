package modelmerger

import (
	"cmp"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/threatcat-dev/threatcat/internal/common"
)

type ModelMerger struct {
	cl     changelog
	logger *slog.Logger
}

// reduce coupling with changelog package by using an interface on consumer side
type changelog interface {
	AddEntry(string)
}

// NewModelMerger creates a new ModelMerger instance
func NewModelMerger(cl changelog, logger *slog.Logger) *ModelMerger {
	return &ModelMerger{
		cl:     cl,
		logger: logger.With("package", "modelmerger", "component", "ModelMerger"),
	}
}

// Merge merges multiple threat models into one.
// It returns an empty threat model if no models are provided.
// If only one model is provided, it returns that model.
// If multiple models are provided, it merges them into one model.
func (mm *ModelMerger) Merge(models []common.ThreatModel) common.ThreatModel {
	switch len(models) {
	case 0:
		mm.logger.Debug("No models received for merging. Returning empty.")
		return common.EmptyThreatModel()
	case 1:
		mm.logger.Debug("One model received for merging. Returning the model.")
		return models[0]
	default:
		mm.logger.Debug("Multiple models received for merging. Beginning merge.", "count", len(models))
		return mm.mergeModels(models)
	}
}

// mergeModels merges multiple threat models into one.
// It merges the assets and extra data of the models.
// It returns a new threat model with the merged assets and extra data.
func (mm *ModelMerger) mergeModels(models []common.ThreatModel) common.ThreatModel {
	mm.logger.Debug("Seperating model assets into assetMap")
	assetMap := make(map[string][]common.Asset)
	for _, model := range models {
		for _, asset := range model.Assets {
			assetMap[asset.ID] = append(assetMap[asset.ID], asset)
		}
	}
	mm.logger.Debug("Model assets have been separated by ID", "distinctAssets", len(assetMap))
	mergedAssets := make([]common.Asset, 0, len(assetMap))
	for _, assets := range assetMap {
		logger := mm.logger.With("assets[0].ID", assets[0].ID)
		// if the lenght of assets is greater than 1, merging is necessary. In the case that there is only
		// 1 asset it needs to be checked if it needs to be persited. The condition for persitance is
		// if the source is not ThreatDragon, this means that the asset needs to be created be the tool.
		// If the source is ThreatDragon, the condition for persitance is if the asset is created be the
		// user. If it is not it is assumed that the asset was previously created by the tool and is now
		// no longer in the original source.
		if len(assets) > 1 {
			logger.Debug("Multiple Asset instances for this ID. Merging.", "assetCount", len(assets))
			mergedAssets = append(mergedAssets, mergeableAssets(assets).merge(logger))
		} else if common.GetOr(assets[0].Extra, "IsGeneratedByUser", false) || assets[0].Source != common.DataSourceThreatDragon {
			logger.Debug("Asset was found in a single original source. Keeping.")
			mergedAssets = append(mergedAssets, assets[0])
		} else {
			logger.Debug("Asset was no longer found in its original source. Removing.")
			mm.cl.AddEntry(fmt.Sprintf("Removed asset '%s' that was no longer found in its original source.", assets[0].DisplayName))
		}
	}

	// sort merged Assets slices by ID to provide deterministic order of items (ascending order)
	slices.SortFunc(mergedAssets, func(a, b common.Asset) int {
		return cmp.Compare(a.ID, b.ID)
	})

	mm.logger.Info("Merging model extras")
	modelExtra := mm.mergeModelExtras(models)
	mm.logger.Info("Successfully merged model extras", "length", len(modelExtra))
	return common.ThreatModel{
		Assets: mergedAssets,
		Extra:  modelExtra,
	}
}

func (mm *ModelMerger) mergeModelExtras(models []common.ThreatModel) map[string]any {
	extraMap := make(map[string]any)
	for _, model := range models {
		maps.Copy(extraMap, model.Extra)
		//TODO: Are there cases, where we can't just overwrite the value?
		//Can the same key occur in different models?
	}
	mm.logger.Debug("Created extra map from model")
	return extraMap
}

// this type alias has been defined to seperate asset merging logic into methods for this type.
type mergeableAssets []common.Asset

// type mergeableAssets struct {
//
// 	asset []common.Asset
// }

// mergeAsset merges multiple assets into one.
// It panics if there are no assets to merge.
// If only one asset is provided, it returns that asset.
// It merges the display name, type, source, and extra data of the assets.
func (ma mergeableAssets) merge(logger *slog.Logger) common.Asset {
	logger.Debug("Merging assets")
	if len(ma) == 0 {
		panic("No assets to merge")
	} else if len(ma) == 1 {
		logger.Debug("Only one asset to merge. Returning directly.")
		return ma[0]
	}

	mergedAsset := common.Asset{
		ID:          ma[1].ID,
		DisplayName: ma.displayName(logger),
		Type:        ma.assetType(logger),
		Source:      common.DataSourceMerged,
		Extra:       ma.extra(logger),
	}
	logger.Debug("Successfully merged asstets", "mergedAsset", mergedAsset)
	return mergedAsset
}

// displayName() returns the display name of the merged asset.
// It uses the following priority order:
// 1. The display name of an asset with source DataSourceThreatDragon
// 2. The display name of an asset with source DataSourceDockerCompose
// 3. The display name of an asset with source DataSourceUnknown
func (ma mergeableAssets) displayName(logger *slog.Logger) string {
	var threatDragonName, dockerComposeName, unknownName *string
	for _, asset := range ma {
		switch asset.Source {
		case common.DataSourceThreatDragon:
			threatDragonName = &asset.DisplayName
		case common.DataSourceDockerCompose:
			dockerComposeName = &asset.DisplayName
		case common.DataSourceUnknown:
			unknownName = &asset.DisplayName
		}
	}
	if threatDragonName != nil {
		logger.Debug("Found display name for asset", "threatDragonName", *threatDragonName)
		return *threatDragonName
	} else if dockerComposeName != nil {
		logger.Debug("Found display name for asset", "dockerComposeName", *dockerComposeName)
		return *dockerComposeName
	} else if unknownName != nil {
		logger.Debug("Found display name for asset", "unknownName", *unknownName)
		return *unknownName
	} else {
		logger.Debug("Found no display name for asset")
		return ""
	}
}

// assetType() returns the type of the merged asset.
// It uses the following priority order:
// 1. The type of an asset with source DataSourceDockerCompose
// 2. The type of an asset with source DataSourceThreatDragon
// 3. The type of an asset with source DataSourceUnknown
func (ma mergeableAssets) assetType(logger *slog.Logger) common.AssetType {
	var dockerComposeType, threatDragonType, unknownType *common.AssetType
	for _, asset := range ma {
		switch asset.Source {
		case common.DataSourceDockerCompose:
			dockerComposeType = &asset.Type
		case common.DataSourceThreatDragon:
			threatDragonType = &asset.Type
		case common.DataSourceUnknown:
			unknownType = &asset.Type
		}
	}
	if dockerComposeType != nil {
		logger.Debug("Found asset type", "dockerComposeType", dockerComposeType.String())
		return *dockerComposeType
	} else if threatDragonType != nil {
		logger.Debug("Found asset type", "threatDragonType", threatDragonType.String())
		return *threatDragonType
	} else if unknownType != nil {
		logger.Debug("Found asset type", "unknownType", unknownType.String())
		return *unknownType
	} else {
		logger.Debug("Found asset type", "AssetTypeUnknown", common.AssetTypeUnknown.String())
		return common.AssetTypeUnknown
	}
}

// extra() returns the extra data of the merged asset.
// It merges the extra data maps into one.
func (ma mergeableAssets) extra(logger *slog.Logger) map[string]any {
	extraMap := make(map[string]any)
	logger.Debug("Created extra map")
	for _, asset := range ma {
		maps.Copy(extraMap, asset.Extra)
		//TODO: Are there cases, where we can't just overwrite the value?
		//Can the same key occur in the same asset from different sources?
	}
	logger.Debug("Successfully merged extras")
	return extraMap
}
