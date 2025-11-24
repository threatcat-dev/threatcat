package modelmerger

import (
	"cmp"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"

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
	dataflowMap := make(map[string][]common.DataFlow)
	boundaryMap := make(map[string][]common.TrustBoundary)
	for _, model := range models {
		for _, asset := range model.Assets {
			assetMap[asset.ID] = append(assetMap[asset.ID], asset)
		}
		for _, dataflow := range model.DataFlows {
			dataflowMap[dataflow.ID] = append(dataflowMap[dataflow.ID], dataflow)
		}
		for _, boundary := range model.Boundaries {
			boundaryMap[boundary.ID] = append(boundaryMap[boundary.ID], boundary)
		}
	}
	mm.logger.Debug("Model assets, dataflows and boundaries have been grouped by ID", "distinctAssets", len(assetMap), "distinctDataflows", len(dataflowMap), "distinctBoundaries", len(boundaryMap))

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
			mergedAssets = append(mergedAssets, mergeableAssets(assets).merge(logger, mm.cl))
		} else if common.GetOr(assets[0].Extra, "IsGeneratedByUser", false) || assets[0].Source != common.DataSourceThreatDragon {
			logger.Debug("Asset was found in a single original source. Keeping.")
			mergedAssets = append(mergedAssets, assets[0])
		} else {
			logger.Debug("Asset was no longer found in its original source. Removing.")
			mm.cl.AddEntry(fmt.Sprintf("Removed asset '%s' that was no longer found in its original source.", assets[0].DisplayName))
		}
	}

	mergedBoundaries := make([]common.TrustBoundary, 0, len(boundaryMap))
	for _, boundaries := range boundaryMap {
		logger := mm.logger.With("boundaries[0].ID", boundaries[0].ID)

		if len(boundaries) > 1 {
			logger.Debug("Multiple TrustBoundary instaces for this ID. Merging.", "bondaryCount", len(boundaries))
			mergedBoundaries = append(mergedBoundaries, mergeableBoundaries(boundaries).merge(mergedAssets, logger))
		} else if boundaries[0].Source != common.DataSourceThreatDragon {
			logger.Debug("Boundary was found in a single original source. Keeping.")
			mergedBoundaries = append(mergedBoundaries, boundaries[0])
		} else {
			logger.Debug("Boundary was no longer found in its original source. Removing.")
			mm.cl.AddEntry(fmt.Sprintf("Removed trust boundary '%s' that was no longer found in its original source.", boundaries[0].DisplayName))
		}
	}

	// sort merged Assets slices by ID to provide deterministic order of items (ascending order)
	slices.SortFunc(mergedAssets, func(a, b common.Asset) int {
		return cmp.Compare(a.ID, b.ID)
	})

	mergedDataflows := make([]common.DataFlow, 0, len(dataflowMap))
	for _, dataflows := range dataflowMap {
		logger := mm.logger.With("dataflows[0].ID", dataflows[0].ID)
		if len(dataflows) > 1 {
			// TODO: Implement
			logger.Error("Not yet implemented")
			panic("not yet implemented")
		} else {
			// TODO: Don't just keep the single dataflow. Reference asset logic above
			mergedDataflows = append(mergedDataflows, dataflows[0])
		}
	}
	// sort merged boundaries by ID to provide deterministic oder of items (ascending order)
	slices.SortFunc(mergedBoundaries, func(a, b common.TrustBoundary) int {
		return cmp.Compare(a.ID, b.ID)
	})

	mm.logger.Info("Merging model extras")
	modelExtra := mm.mergeModelExtras(models)
	mm.logger.Info("Successfully merged model extras", "length", len(modelExtra))
	return common.ThreatModel{
		Assets:     mergedAssets,
		DataFlows:  mergedDataflows,
		Boundaries: mergedBoundaries,
		Extra:      modelExtra,
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

// merge merges multiple assets into one.
// It panics if there are no assets to merge.
// If only one asset is provided, it returns that asset.
// It merges the display name, type, source, and extra data of the assets.
func (ma mergeableAssets) merge(logger *slog.Logger, cl changelog) common.Asset {
	logger.Debug("Merging assets")
	if len(ma) == 0 {
		panic("No assets to merge")
	} else if len(ma) == 1 {
		logger.Debug("Only one asset to merge. Returning directly.")
		return ma[0]
	}

	mergedAsset := common.Asset{
		ID:          ma[0].ID,
		DisplayName: ma.displayName(logger),
		Type:        ma.assetType(logger),
		Threats:     ma.threats(logger, cl),
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
	priority := []common.DataSource{
		common.DataSourceMerged,
		common.DataSourceThreatDragon,
		common.DataSourceDockerCompose,
		common.DataSourceUnknown,
	}

	for _, p := range priority {
		for _, asset := range ma {
			if asset.Source == p {
				logger.Debug("Found display name for asset",
					"source", p,
					"displayName", asset.DisplayName)
				return asset.DisplayName
			}
		}
	}

	logger.Debug("Found no display name for asset in priority order. Using any name.")
	return ""
}

// assetType() returns the type of the merged asset.
// It uses the following priority order:
// 1. The type of an asset with source DataSourceDockerCompose
// 2. The type of an asset with source DataSourceThreatDragon
// 3. The type of an asset with source DataSourceUnknown
func (ma mergeableAssets) assetType(logger *slog.Logger) common.AssetType {
	priority := []common.DataSource{
		common.DataSourceDockerCompose,
		common.DataSourceThreatDragon,
		common.DataSourceUnknown,
	}

	for _, p := range priority {
		for _, asset := range ma {
			if asset.Source == p {
				logger.Debug("Found asset type", "source", p, "type", asset.Type.String())
				return asset.Type
			}
		}
	}

	logger.Debug("Found asset type", "type", common.AssetTypeUnknown.String())
	return common.AssetTypeUnknown
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

// threats() returns the threats of the merged asset.
// It uses the following priority order for each threat if found:
// 1. priority source DataSourceThreatDragon
// 2. priority source DataSourceDockerCompose
// 3. priority source DataSourceUnknown
func (ma mergeableAssets) threats(logger *slog.Logger, cl changelog) []common.Threat {

	var threatsToReturn []common.Threat
	var idMap = make(map[string][]common.Threat)

	for _, asset := range ma {
		for _, threat := range asset.Threats {
			// only consider supported valid threats for merging
			if threat.ModelType != common.NotSupported && threat.Type != common.ThreatTypeUnknown {
				idMap[threat.ID] = append(idMap[threat.ID], threat)
			}
		}
	}

	for id, threats := range idMap {
		// sort threats by source priority: ThreatDragon > DockerCompose > Unknown
		sort.Slice(threats, func(i, j int) bool {
			return threats[i].Source < threats[j].Source
		})
		idMap[id] = threats
	}

	for _, threats := range idMap {
		// pick the highest priority threat for this ID
		selectedThreat := &threats[0]
		// check if threat needs to be marked as mitigated
		if len(threats) == 1 && threats[0].Source == common.DataSourceThreatDragon && !threats[0].IsGeneratedByUser {
			logger.Debug("This threat was generated by the tool and is no longer present in the original source. It will be marked as mitigated in the merged model.", "threat", common.TypeString(selectedThreat.Type)+" "+selectedThreat.Title)
			cl.AddEntry(fmt.Sprintf("Threat '%s' was not found in the original source anymore. Therefore it will be marked as mitigated", common.TypeString(selectedThreat.Type)+" "+selectedThreat.Title))
			selectedThreat.Status = common.Mitigated
		}
		threatsToReturn = append(threatsToReturn, *selectedThreat)
		logger.Debug("Added threat to merged asset", "threat", common.TypeString(selectedThreat.Type)+" "+selectedThreat.Title)
	}

	return threatsToReturn
}

// this type alias has been defined to seperate boundary merging logic into methods for this type.
type mergeableBoundaries []common.TrustBoundary

// merge merges multiple boundaries into one.
// It panics if there are not boundaries to merge.
// If only one boundary is provided, it returns that boundary.
// It merges display name, contained assets, and extra data.
// The merged assets slice is required to exclude no longer existing assets from the contained assets slice.
func (mb mergeableBoundaries) merge(mergedAssets []common.Asset, logger *slog.Logger) common.TrustBoundary {
	logger.Debug("Merging boundaries")
	if len(mb) == 0 {
		panic("No boundaries to merge")
	} else if len(mb) == 1 {
		logger.Debug("Only one boundary to merge. Returning directly.")
		return mb[0]
	}

	mergedBoundary := common.TrustBoundary{
		ID:              mb[0].ID,
		DisplayName:     mb.displayName(logger),
		Source:          common.DataSourceMerged,
		ContainedAssets: mb.containedAssets(mergedAssets, logger),
		Extra:           mb.extra(logger),
	}

	logger.Debug("Successfully merged boundaries", "mergedBoundary", mergedBoundary)
	return mergedBoundary
}

// displayName() returns the display name of the merged trust boundary.
// It uses the following priority order:
// 1. The display name of a boundary with source DataSourceThreatDragon
// 2. The display name of a boundary with source DataSourceDockerCompose
// 3. The display name of a boundary with source DataSourceUnknown
func (mb mergeableBoundaries) displayName(logger *slog.Logger) string {
	priority := []common.DataSource{
		common.DataSourceThreatDragon,
		common.DataSourceDockerCompose,
		common.DataSourceUnknown,
	}

	for _, p := range priority {
		for _, asset := range mb {
			if asset.Source == p {
				logger.Debug("Found display name for boundary",
					"source", p,
					"displayName", asset.DisplayName)
				return asset.DisplayName
			}
		}
	}

	logger.Debug("Found no display name for boundary in priority order. Using any name.")
	return mb[0].DisplayName
}

// containedAssets will merge the ID list of contained assets.
// Assets that no longer exist will not be included.
func (mb mergeableBoundaries) containedAssets(mergedAssets []common.Asset, logger *slog.Logger) []string {
	logger.Debug("Merging contained assets")
	containedAssets := make([]string, 0)

	for _, boundary := range mb {
		for _, containedAsset := range boundary.ContainedAssets {
			if slices.Contains(containedAssets, containedAsset) {
				continue // already stored
			}
			if !slices.ContainsFunc(mergedAssets, func(a common.Asset) bool {
				return a.ID == containedAsset
			}) {
				continue // no longer exists
			}

			containedAssets = append(containedAssets, containedAsset)
		}
	}

	logger.Debug("Successfully merged contained assets", "count", len(containedAssets))
	return containedAssets
}

// extra() returns the extra data of the merged boundary.
// It merges the extra data maps into one.
func (mb mergeableBoundaries) extra(logger *slog.Logger) map[string]any {
	extraMap := make(map[string]any)
	logger.Debug("Created extra map")
	for _, asset := range mb {
		maps.Copy(extraMap, asset.Extra)
		//TODO: Are there cases, where we can't just overwrite the value?
		//Can the same key occur in the same asset from different sources?
	}
	logger.Debug("Successfully merged extras")
	return extraMap
}
