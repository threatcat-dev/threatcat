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

// Strategy function type definitions for model merging
type AssetDisplayNameStrategy func([]common.Asset, *slog.Logger) string
type AssetTypeStrategy func([]common.Asset, *slog.Logger) common.AssetType
type BoundaryDisplayNameStrategy func([]common.TrustBoundary, *slog.Logger) string
type ThreatPrioritizationStrategy func([]common.Threat) []common.Threat
type DataFlowDisplayNameStrategy func([]common.DataFlow, *slog.Logger) string
type DataFlowTechnicalPropertiesStrategy func([]common.DataFlow, *slog.Logger) common.DataFlow

type ModelMerger struct {
	cl                             changelog
	logger                         *slog.Logger
	assetDisplayNameStrategy       AssetDisplayNameStrategy
	assetTypeStrategy              AssetTypeStrategy
	boundaryDisplayNameStrategy    BoundaryDisplayNameStrategy
	prioritizeThreatsStrategy      ThreatPrioritizationStrategy
	dataFlowDisplayNameStrategy    DataFlowDisplayNameStrategy
	dataFlowTechnicalPropsStrategy DataFlowTechnicalPropertiesStrategy
}

// MergeConfig holds the strategies for merging a specific type of component.
type MergeConfig[T any] struct {
	Label      string
	GetID      func(T) string
	GetName    func(T) string
	ShouldKeep func(T) bool
	DoMerge    func(items []T, l *slog.Logger) T
}

// reduce coupling with changelog package by using an interface on consumer side
type changelog interface {
	AddEntry(string)
}

// NewModelMerger creates a new ModelMerger instance that uses either automatic or manual
// merge strategies. In manual mode, the user is prompted to resolve conflicts when merging
// assets, boundaries, and threats. In automatic mode, predefined priority rules are used.
func NewModelMerger(cl changelog, logger *slog.Logger, manualMode bool) *ModelMerger {
	mm := &ModelMerger{
		cl:     cl,
		logger: logger.With("package", "modelmerger", "component", "ModelMerger"),
	}

	if manualMode {
		mm.assetDisplayNameStrategy = assetDisplayNameManual
		mm.assetTypeStrategy = assetTypeManual
		mm.boundaryDisplayNameStrategy = boundaryDisplayNameManual
		mm.prioritizeThreatsStrategy = pioritizeThreatsManual
		mm.dataFlowDisplayNameStrategy = dataFlowDisplayNameManual
		mm.dataFlowTechnicalPropsStrategy = dataFlowTechnicalPropertiesManual
	} else {
		mm.assetDisplayNameStrategy = assetDisplayNameAuto
		mm.assetTypeStrategy = assetTypeAuto
		mm.boundaryDisplayNameStrategy = boundaryDisplayNameAuto
		mm.prioritizeThreatsStrategy = prioritizeThreatsAuto
		mm.dataFlowDisplayNameStrategy = dataFlowDisplayNameAuto
		mm.dataFlowTechnicalPropsStrategy = dataFlowTechnicalPropertiesAuto
	}

	return mm
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

// mergeModelComponents executes the standard merging lifecycle for a collection of model components.
//
// The function performs the following steps:
//  1. Groups items by ID to identify collisions.
//  2. If multiple items exist for an ID, it invokes a merge via cfg.DoMerge.
//  3. If a single item exists, cfg.ShouldKeep determines if the item
//     should persist or be removed (logging a removal entry in the changelog).
//  4. Sorts the result slice by ID to ensure deterministic output.
func mergeModelComponents[T any](
	items []T,
	logger *slog.Logger,
	cl changelog,
	cfg MergeConfig[T],
) []T {
	groups := groupByID(items, cfg.GetID)
	results := make([]T, 0, len(groups))

	for id, group := range groups {
		l := logger.With("id", id, "type", cfg.Label)

		if len(group) > 1 {
			l.Debug("Multiple instances found. Merging.", "count", len(group))
			results = append(results, cfg.DoMerge(group, l))
		} else if cfg.ShouldKeep(group[0]) {
			results = append(results, group[0])
		} else {
			l.Debug("Item no longer found in original source. Removing.")
			cl.AddEntry(fmt.Sprintf(
				"Removed %s '%s' that was no longer found in its original source.",
				cfg.Label,
				cfg.GetName(group[0]),
			))
		}
	}

	// Sort merged items by ID to provide deterministic order (ascending)
	slices.SortFunc(results, func(a, b T) int {
		return cmp.Compare(cfg.GetID(a), cfg.GetID(b))
	})

	return results
}

// mergeComponentExtras aggregates metadata from a slice of components into a single map.
//
// It uses the provided extract function to access the 'Extra' map of each item
// and merges them into a unified result. In the event of duplicate keys across
// items, the value from the item appearing later in the slice will overwrite
// previous values.
//
// Type Parameters:
//   - T: The component type (e.g., Asset, DataFlow) containing metadata.
func mergeComponentExtras[T any](logger *slog.Logger, items []T, extract func(T) map[string]any) map[string]any {
	merged := make(map[string]any)
	for _, item := range items {
		maps.Copy(merged, extract(item))
	}
	logger.Debug("Successfully merged extras")
	return merged
}

// collectComponents flattens the nested slices of a threat model collection into
// individual slices of Assets, DataFlows, and TrustBoundaries.
//
// This serves as a preparation step for the merging process, allowing the
// merger to process all components of a specific type in bulk regardless
// of which source model they originated from.
func (mm *ModelMerger) collectComponents(models []common.ThreatModel) ([]common.Asset, []common.DataFlow, []common.TrustBoundary) {
	var assets []common.Asset
	var dfs []common.DataFlow
	var boundaries []common.TrustBoundary
	for _, m := range models {
		assets = append(assets, m.Assets...)
		dfs = append(dfs, m.DataFlows...)
		boundaries = append(boundaries, m.Boundaries...)
	}
	return assets, dfs, boundaries
}

// mergeModels merges multiple threat models into one.
// It merges the assets and extra data of the models.
// It returns a new threat model with the merged assets and extra data.
func (mm *ModelMerger) mergeModels(models []common.ThreatModel) common.ThreatModel {
	mm.logger.Debug("Grouping model components by ID")
	assets, dfs, boundaries := mm.collectComponents(models)

	// Merge Assets
	mergedAssets := mergeModelComponents(assets, mm.logger, mm.cl, MergeConfig[common.Asset]{
		Label:   "Asset",
		GetID:   func(a common.Asset) string { return a.ID },
		GetName: func(a common.Asset) string { return a.DisplayName },
		ShouldKeep: func(a common.Asset) bool {
			return common.GetOr(a.Extra, "IsGeneratedByUser", false) || a.Source != common.DataSourceThreatDragon
		},
		DoMerge: func(items []common.Asset, l *slog.Logger) common.Asset {
			return newMergeableAssets(items, mm.assetDisplayNameStrategy, mm.assetTypeStrategy, mm.prioritizeThreatsStrategy).
				merge(l, mm.cl)
		},
	})

	// Merge Boundaries
	mergedBoundaries := mergeModelComponents(boundaries, mm.logger, mm.cl, MergeConfig[common.TrustBoundary]{
		Label:   "Boundary",
		GetID:   func(b common.TrustBoundary) string { return b.ID },
		GetName: func(b common.TrustBoundary) string { return b.DisplayName },
		ShouldKeep: func(b common.TrustBoundary) bool {
			return b.Source != common.DataSourceThreatDragon
		},
		DoMerge: func(items []common.TrustBoundary, l *slog.Logger) common.TrustBoundary {
			return newMergeableBoundaries(items, mm.boundaryDisplayNameStrategy).
				merge(mergedAssets, l)
		},
	})

	// Merge DataFlows
	mergedDataflows := mergeModelComponents(dfs, mm.logger, mm.cl, MergeConfig[common.DataFlow]{
		Label:   "DataFlow",
		GetID:   func(df common.DataFlow) string { return df.ID },
		GetName: func(df common.DataFlow) string { return df.Name },
		ShouldKeep: func(df common.DataFlow) bool {
			return df.DataSource != common.DataSourceThreatDragon || df.IsGeneratedByUser
		},
		DoMerge: func(items []common.DataFlow, l *slog.Logger) common.DataFlow {
			return newMergeableDataFlows(items, mm.dataFlowDisplayNameStrategy, mm.dataFlowTechnicalPropsStrategy, mm.prioritizeThreatsStrategy).
				merge(l, mm.cl)
		},
	})

	// Construct output Model
	return common.ThreatModel{
		Assets:     mergedAssets,
		DataFlows:  mergedDataflows,
		Boundaries: mergedBoundaries,
		Extra:      mm.mergeModelExtras(models),
	}
}

// mergeModelExtras aggregates the 'Extra' metadata from a slice of threat models
// into a single map. If duplicate keys exist across models, the value from
// the later model in the slice will overwrite previous ones.
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

// mergeableAssets encapsulates multiple assets with the same ID along with the strategy
// functions used to merge them (either automatically or manually based on user preference).
type mergeableAssets struct {
	as                []common.Asset
	displayName       AssetDisplayNameStrategy
	assetType         AssetTypeStrategy
	prioritizeThreats ThreatPrioritizationStrategy
}

// newMergeableAssets creates a new mergeableAssets instance with the specified assets
// and merge strategies.
func newMergeableAssets(b []common.Asset,
	displayName AssetDisplayNameStrategy,
	assetType AssetTypeStrategy,
	prioritizeThreats ThreatPrioritizationStrategy) mergeableAssets {
	return mergeableAssets{
		as:                b,
		displayName:       displayName,
		assetType:         assetType,
		prioritizeThreats: prioritizeThreats,
	}
}

// merge merges multiple assets into one, automatically or manually.
// If only one asset is provided, it returns that asset.
// It merges the display name, type, source, and extra data of the assets.
func (ma mergeableAssets) merge(logger *slog.Logger, cl changelog) common.Asset {
	var mergedAsset common.Asset

	logger.Debug("Merging assets")
	if len(ma.as) == 1 {
		logger.Debug("Only one asset to merge. Returning directly.")
		return ma.as[0]
	}
	//merge asset manually or automatically depending on setting
	mergedAsset = common.Asset{
		ID:          ma.as[0].ID,
		DisplayName: ma.displayName(ma.as, logger),
		Type:        ma.assetType(ma.as, logger),
		Threats:     ma.threats(logger, cl),
		Source:      common.DataSourceMerged,
		Extra:       ma.extra(logger),
	}
	logger.Debug("Successfully merged assets", "mergedAsset", mergedAsset)
	return mergedAsset
}

// mergeableDataFlows encapsulates multiple dataflows with the same ID along with the strategy
// functions used to merge them (either automatically or manually based on user preference).
type mergeableDataFlows struct {
	dfs               []common.DataFlow
	displayName       DataFlowDisplayNameStrategy
	technicalProps    DataFlowTechnicalPropertiesStrategy
	prioritizeThreats ThreatPrioritizationStrategy
}

// newMergeableDataFlows creates a new mergeableDataFlows instance with the specified dataflows
// and merge strategies.
func newMergeableDataFlows(
	dfs []common.DataFlow,
	displayName DataFlowDisplayNameStrategy,
	technicalProps DataFlowTechnicalPropertiesStrategy,
	prioritizeThreats ThreatPrioritizationStrategy,
) mergeableDataFlows {
	return mergeableDataFlows{
		dfs:               dfs,
		displayName:       displayName,
		technicalProps:    technicalProps,
		prioritizeThreats: prioritizeThreats,
	}
}

// merge returns the merged dataflow.
// If only one dataflow is provided, it returns that dataflow.
// It merges the display name, technical properties, threats, and extra data.
func (mdf mergeableDataFlows) merge(logger *slog.Logger, cl changelog) common.DataFlow {
	logger.Debug("Merging dataflows")
	if len(mdf.dfs) == 1 {
		logger.Debug("Only one dataflow to merge. Returning directly.")
		return mdf.dfs[0]
	}
	genUser := false
	// New condition: If user generated Dataflow is found, it is directly returned without merge
	for _, userDataFlow := range mdf.dfs {
		if userDataFlow.IsGeneratedByUser {
			genUser = true
		}
	}
	// New condition

	// Get the technical properties from the prioritized dataflow
	technicalProps := mdf.technicalProps(mdf.dfs, logger)

	mergedDataFlow := common.DataFlow{
		ID:                mdf.dfs[0].ID,
		Name:              mdf.displayName(mdf.dfs, logger),
		Protocol:          technicalProps.Protocol,
		Encrypted:         technicalProps.Encrypted,
		PublicNetwork:     technicalProps.PublicNetwork,
		Source:            technicalProps.Source,
		SourceID:          technicalProps.SourceID,
		Target:            technicalProps.Target,
		TargetID:          technicalProps.TargetID,
		Bidirectional:     technicalProps.Bidirectional,
		Threats:           mdf.threats(logger, cl),
		DataSource:        common.DataSourceMerged,
		IsGeneratedByUser: genUser,
		Extra:             mdf.extra(logger),
	}

	logger.Debug("Successfully merged dataflows", "mergedDataFlow", mergedDataFlow)
	return mergedDataFlow
}

// manualMerge is a generic helper that implements the common pattern for manual merging:
// 1. Call auto function to get automatic result
// 2. Check if all values are equal (if so, use auto result)
// 3. Ask user to confirm auto result
// 4. If rejected, prompt user to select manually
func manualMerge[T any, V comparable](
	items []T,
	autoFunc func([]T, *slog.Logger) V,
	valueExtractor func(T) V,
	sourceExtractor func(T) common.DataSource,
	valueStringer func(V) string,
	itemID string,
	itemType string,
	logger *slog.Logger,
) V {
	autoResult := autoFunc(items, logger)

	// Extract all values
	values := make([]V, len(items))
	for i, item := range items {
		values[i] = valueExtractor(item)
	}

	// If all equal, return auto result
	if allElementsEqual(values) {
		return autoResult
	}

	// Ask for confirmation
	if getUserConfirmation(
		fmt.Sprintf("Changes occurred in %s of item with ID: %s", itemType, itemID),
		fmt.Sprintf("Automerge would select: %s", valueStringer(autoResult)),
	) {
		return autoResult
	}

	// Manual selection
	fmt.Println("Please select one of the following merging options:")
	for j := range items {
		fmt.Printf("%d: %s input source: %s\n",
			j,
			valueStringer(valueExtractor(items[j])),
			sourceExtractor(items[j]).ShortString())
	}

	for {
		fmt.Println()
		idx, err := getUserInputAsUnsignedInt()

		if err != nil || idx >= uint(len(items)) {
			fmt.Println("invalid input argument")
		} else {
			return valueExtractor(items[idx])
		}
	}
}

// assetDisplayNameAuto() returns the display name of the merged asset.
// It uses the following priority order:
// 1. The display name of an asset with source DataSourceThreatDragon
// 2. The display name of an asset with source DataSourceDockerCompose
// 3. The display name of an asset with source DataSourceUnknown
// 4. The display name of an asset with source DataSourceMerged
func assetDisplayNameAuto(as []common.Asset, logger *slog.Logger) string {
	return getHighestPrioValue(
		as,
		map[common.DataSource]int{
			common.DataSourceThreatDragon:  0,
			common.DataSourceDockerCompose: 1,
			common.DataSourceUnknown:       2,
			common.DataSourceMerged:        3,
		},
		func(asset common.Asset) common.DataSource { return asset.Source },
		func(asset common.Asset) string { return asset.DisplayName },
		logger,
		"Found display name for asset",
		"Found no display name for asset in priority order. Using any name.",
		"",
	)
}

// assetDisplayNameManual prompts the user to manually select a display name when merging assets,
// falling back to AssetDisplayNameAuto if all display names are identical.
func assetDisplayNameManual(as []common.Asset, logger *slog.Logger) string {
	return manualMerge(
		as,
		assetDisplayNameAuto,
		func(a common.Asset) string { return a.DisplayName },
		func(a common.Asset) common.DataSource { return a.Source },
		func(s string) string { return s },
		as[0].ID,
		"display name of Asset",
		logger,
	)
}

// dataFlowDisplayNameAuto returns the display name of a dataflow using automatic priority:
// ThreatDragon > DockerCompose > Unknown (user input takes precedence)
func dataFlowDisplayNameAuto(dfs []common.DataFlow, logger *slog.Logger) string {
	return getHighestPrioValue(
		dfs,
		map[common.DataSource]int{
			common.DataSourceThreatDragon:  0,
			common.DataSourceDockerCompose: 1,
			common.DataSourceUnknown:       2,
		},
		func(df common.DataFlow) common.DataSource { return df.DataSource },
		func(df common.DataFlow) string { return df.Name },
		logger,
		"Found display name for dataflow",
		"Found no display name for dataflow in priority order. Using any name.",
	)
}

// dataFlowDisplayNameManual prompts the user to manually select a display name when merging dataflows,
// falling back to DataFlowDisplayNameAuto if all display names are identical.
func dataFlowDisplayNameManual(dfs []common.DataFlow, logger *slog.Logger) string {
	return manualMerge(
		dfs,
		dataFlowDisplayNameAuto,
		func(df common.DataFlow) string { return df.Name },
		func(df common.DataFlow) common.DataSource { return df.DataSource },
		func(s string) string { return s },
		dfs[0].ID,
		"display name of DataFlow",
		logger,
	)
}

// dataFlowTechnicalPropertiesAuto returns the technical properties of a dataflow using automatic priority:
// DockerCompose > ThreatDragon > Unknown (auto-detected technical details take precedence)
func dataFlowTechnicalPropertiesAuto(dfs []common.DataFlow, logger *slog.Logger) common.DataFlow {
	return getHighestPrioValue(
		dfs,
		map[common.DataSource]int{
			common.DataSourceDockerCompose: 0,
			common.DataSourceThreatDragon:  1,
			common.DataSourceUnknown:       2,
		},
		func(df common.DataFlow) common.DataSource { return df.DataSource },
		func(df common.DataFlow) common.DataFlow { return df },
		logger,
		"Found technical properties for dataflow",
		"Found no technical properties for dataflow in priority order. Using any dataflow.",
	)
}

// dataFlowTechnicalPropertiesManual prompts the user to manually select technical properties when merging dataflows,
// falling back to DataFlowTechnicalPropertiesAuto if all properties are identical.
func dataFlowTechnicalPropertiesManual(dfs []common.DataFlow, logger *slog.Logger) common.DataFlow {
	autoResult := dataFlowTechnicalPropertiesAuto(dfs, logger)

	// Check if all technical properties are equal
	allEqual := true
	for i := 1; i < len(dfs); i++ {
		if dfs[i].Protocol != dfs[0].Protocol ||
			dfs[i].Encrypted != dfs[0].Encrypted ||
			dfs[i].PublicNetwork != dfs[0].PublicNetwork ||
			dfs[i].SourceID != dfs[0].SourceID ||
			dfs[i].TargetID != dfs[0].TargetID ||
			dfs[i].Bidirectional != dfs[0].Bidirectional {
			allEqual = false
			break
		}
	}

	if allEqual {
		return autoResult
	}

	// Ask for confirmation
	if getUserConfirmation(
		fmt.Sprintf("Changes occurred in technical properties of DataFlow with ID: %s", dfs[0].ID),
		fmt.Sprintf("Protocol: %s, Encrypted: %v, PublicNetwork: %v, Source: %s, Target: %s, Bidirectional: %v",
			autoResult.Protocol, autoResult.Encrypted, autoResult.PublicNetwork,
			autoResult.Source, autoResult.Target, autoResult.Bidirectional),
	) {
		return autoResult
	}

	// Manual selection
	fmt.Println("Please select one of the following dataflows for technical properties:")
	for j := range dfs {
		fmt.Printf("%d: Protocol: %s, Encrypted: %v, PublicNetwork: %v, Source: %s, Target: %s, Bidirectional: %v (from %s)\n",
			j, dfs[j].Protocol, dfs[j].Encrypted, dfs[j].PublicNetwork,
			dfs[j].Source, dfs[j].Target, dfs[j].Bidirectional,
			dfs[j].DataSource.ShortString())
	}

	for {
		fmt.Println()
		idx, err := getUserInputAsUnsignedInt()

		if err != nil || idx >= uint(len(dfs)) {
			fmt.Println("invalid input argument")
		} else {
			return dfs[idx]
		}
	}
}

// assetType() returns the type of the merged asset.
// It uses the following priority order:
// 1. The type of an asset with source DataSourceDockerCompose
// 2. The type of an asset with source DataSourceThreatDragon
// 3. The type of an asset with source DataSourceUnknown
func assetTypeAuto(as []common.Asset, logger *slog.Logger) common.AssetType {
	return getHighestPrioValue(
		as,
		map[common.DataSource]int{
			common.DataSourceDockerCompose: 0,
			common.DataSourceThreatDragon:  1,
			common.DataSourceUnknown:       2,
		},
		func(asset common.Asset) common.DataSource { return asset.Source },
		func(asset common.Asset) common.AssetType { return asset.Type },
		logger,
		"Found asset type",
		"Found asset type",
		common.AssetTypeUnknown,
	)
}

// assetTypeManual prompts the user to manually select an asset type when merging assets,
// falling back to AssetTypeAuto if all asset types are identical.
func assetTypeManual(as []common.Asset, logger *slog.Logger) common.AssetType {
	return manualMerge(
		as,
		assetTypeAuto,
		func(a common.Asset) common.AssetType { return a.Type },
		func(a common.Asset) common.DataSource { return a.Source },
		func(t common.AssetType) string { return t.String() },
		as[0].ID,
		"asset type of Asset",
		logger,
	)
}

// extra() returns the extra data of the merged asset.
// It merges the extra data maps into one.
func (ma mergeableAssets) extra(logger *slog.Logger) map[string]any {
	return mergeComponentExtras(logger, ma.as, func(a common.Asset) map[string]any {
		return a.Extra
	})
}

// ============================= Threats==========================================

// mergeThreatsFromSources is a helper function that merges threats from multiple sources.
// It groups threats by ID, prioritizes them using the provided strategy, and marks
// auto-generated threats as mitigated if they're no longer in the original source.
func mergeThreatsFromSources(
	allThreats []common.Threat,
	prioritizeStrategy ThreatPrioritizationStrategy,
	logger *slog.Logger,
	cl changelog,
) []common.Threat {
	var threatsToReturn []common.Threat
	var idMap = make(map[string][]common.Threat)

	// Group threats by ID, filtering out unsupported threats
	for _, threat := range allThreats {
		// only consider supported valid threats for merging
		if threat.ModelType != common.NotSupported && threat.Type != common.ThreatTypeUnknown {
			idMap[threat.ID] = append(idMap[threat.ID], threat)
		}
	}

	// Prioritize threats for each ID
	for id, threats := range idMap {
		idMap[id] = prioritizeStrategy(threats)
	}

	// Select the highest priority threat for each ID
	for _, threats := range idMap {
		selectedThreat := &threats[0]
		// check if threat needs to be marked as mitigated
		if len(threats) == 1 && threats[0].Source == common.DataSourceThreatDragon && !threats[0].IsGeneratedByUser {
			logger.Debug("This threat was generated by the tool and is no longer present in the original source. It will be marked as mitigated in the merged model.", "threat", selectedThreat.Type.String()+" "+selectedThreat.Title)
			cl.AddEntry(fmt.Sprintf("Threat '%s' was not found in the original source anymore. Therefore it will be marked as mitigated", selectedThreat.Type.String()+" "+selectedThreat.Title))
			selectedThreat.Status = common.Mitigated
		}
		threatsToReturn = append(threatsToReturn, *selectedThreat)
		logger.Debug("Added threat to merged element", "threat", selectedThreat.Type.String()+" "+selectedThreat.Title)
	}

	return threatsToReturn
}

// prioritizeThreatsAuto sorts threats by source priority: ThreatDragon > DockerCompose > Unknown.
func prioritizeThreatsAuto(threats []common.Threat) []common.Threat {

	// sort threats by source priority: ThreatDragon > DockerCompose > Unknown
	sort.Slice(threats, func(i, j int) bool {
		return threats[i].Source < threats[j].Source
	})
	return threats
}

// allThreatsEquivalent checks if all threats are identical except for their Source field.
func allThreatsEquivalent(threats []common.Threat) bool {
	if len(threats) <= 1 {
		return true
	}

	// Helper to create a copy with the Source field "muted"
	normalize := func(t common.Threat) common.Threat {
		t.Source = 0
		return t
	}

	// Compare all normalized slices to first slice
	first := normalize(threats[0])
	for _, t := range threats[1:] {
		if normalize(t) != first {
			return false
		}
	}

	return true
}

// pioritizeThreatsManual allows the user to manually select which threat should be prioritized.
// If all threats are equivalent (same except for source), it uses automatic prioritization.
func pioritizeThreatsManual(threats []common.Threat) []common.Threat {

	autoThreats := prioritizeThreatsAuto(threats)
	// If threats are all equivalent except for source, use auto prioritization
	if allThreatsEquivalent(threats) {
		return autoThreats
	}

	// ask user if automerge result should be accepted as is
	if getUserConfirmation("Changes occurred in threat priority for Asset with ID: "+threats[0].ID, threats[0].Type.String()) {
		return autoThreats
	}

	// automerge rejected: let user choose a threat manually
	fmt.Println("\nPlease select the threat that should be prioritized as highest:")
	fmt.Println("========================================")
	for j, threat := range threats {
		fmt.Printf("\n[%d] Source: %s\n", j, threat.Source.ShortString())
		fmt.Printf("    Title:       %s\n", threat.Title)
		fmt.Printf("    Type:        %s\n", threat.Type.String())
		fmt.Printf("    Status:      %s\n", threat.Status.String())
		fmt.Printf("    Severity:    %s\n", threat.Severity)

		// Truncate description if too long for readability
		desc := threat.Description
		if len(desc) > 100 {
			desc = desc[:97] + "..."
		}
		if desc != "" {
			fmt.Printf("    Description: %s\n", desc)
		}

		// Truncate mitigation if too long
		mit := threat.Mitigation
		if len(mit) > 100 {
			mit = mit[:97] + "..."
		}
		if mit != "" {
			fmt.Printf("    Mitigation:  %s\n", mit)
		}
	}
	fmt.Println("\n========================================")

	for {
		fmt.Print("Enter selection [0-", len(threats)-1, "]: ")
		idx, err := getUserInputAsUnsignedInt()

		if (err != nil) || (idx >= uint(len(threats))) {
			fmt.Println("Invalid input. Please enter a number between 0 and", len(threats)-1)
		} else {
			// put selected threat to the front of the array
			threats[0], threats[idx] = threats[idx], threats[0]
			return threats
		}
	}
}

// threats() returns the threats of the merged asset.
// It uses the following priority order for each threat if found:
// 1. priority source DataSourceThreatDragon
// 2. priority source DataSourceDockerCompose
// 3. priority source DataSourceUnknown
func (ma mergeableAssets) threats(logger *slog.Logger, cl changelog) []common.Threat {
	// Collect all threats from all assets
	var allThreats []common.Threat
	for _, asset := range ma.as {
		allThreats = append(allThreats, asset.Threats...)
	}

	return mergeThreatsFromSources(allThreats, ma.prioritizeThreats, logger, cl)
}

// threats() returns the threats of the merged dataflow.
// It uses the following priority order for each threat if found:
// 1. priority source DataSourceThreatDragon
// 2. priority source DataSourceDockerCompose
// 3. priority source DataSourceUnknown
func (mdf mergeableDataFlows) threats(logger *slog.Logger, cl changelog) []common.Threat {
	// Collect all threats from all dataflows
	var allThreats []common.Threat
	for _, df := range mdf.dfs {
		allThreats = append(allThreats, df.Threats...)
	}

	return mergeThreatsFromSources(allThreats, mdf.prioritizeThreats, logger, cl)
}

// mergeableBoundaries encapsulates multiple boundaries with the same ID along with the strategy
// function used to merge them (either automatically or manually based on user preference).
type mergeableBoundaries struct {
	bnd         []common.TrustBoundary
	displayName BoundaryDisplayNameStrategy
}

// newMergeableBoundaries creates a new mergeableBoundaries instance with the specified boundaries
// and display name merge strategy.
func newMergeableBoundaries(b []common.TrustBoundary, displayName BoundaryDisplayNameStrategy) mergeableBoundaries {
	return mergeableBoundaries{
		bnd:         b,
		displayName: displayName,
	}
}

// merge merges multiple boundaries into one.
// If only one boundary is provided, it returns that boundary.
// It merges display name, contained assets, and extra data.
// The merged assets slice is required to exclude no longer existing assets from the contained assets slice.
func (mb mergeableBoundaries) merge(mergedAssets []common.Asset, logger *slog.Logger) common.TrustBoundary {
	var mergedBoundary common.TrustBoundary
	logger.Debug("Merging boundaries")
	if len(mb.bnd) == 1 {
		logger.Debug("Only one boundary to merge. Returning directly.")
		return mb.bnd[0]
	}
	mergedBoundary = common.TrustBoundary{
		ID:              mb.bnd[0].ID,
		DisplayName:     mb.displayName(mb.bnd, logger),
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
func boundaryDisplayNameAuto(tb []common.TrustBoundary, logger *slog.Logger) string {
	return getHighestPrioValue(
		tb,
		map[common.DataSource]int{
			common.DataSourceThreatDragon:  0,
			common.DataSourceDockerCompose: 1,
			common.DataSourceUnknown:       2,
		},
		func(boundary common.TrustBoundary) common.DataSource { return boundary.Source },
		func(boundary common.TrustBoundary) string { return boundary.DisplayName },
		logger,
		"Found display name for boundary",
		"Found no display name for boundary in priority order. Using any name.",
	)
}

// boundaryDisplayNameManual prompts the user to manually select a display name when merging boundaries,
// falling back to BoundaryDisplayNameAuto if all display names are identical.
func boundaryDisplayNameManual(tb []common.TrustBoundary, logger *slog.Logger) string {
	return manualMerge(
		tb,
		boundaryDisplayNameAuto,
		func(b common.TrustBoundary) string { return b.DisplayName },
		func(b common.TrustBoundary) common.DataSource { return b.Source },
		func(s string) string { return s },
		tb[0].ID,
		"display name of Boundary",
		logger,
	)
}

// extra() returns the extra data of the merged dataflow.
// It merges the extra data maps into one.
func (mdf mergeableDataFlows) extra(logger *slog.Logger) map[string]any {
	return mergeComponentExtras(logger, mdf.dfs, func(a common.DataFlow) map[string]any {
		return a.Extra
	})
}

// ============================= Additional merges ==========================================
// containedAssets will merge the ID list of contained assets.
// Assets that no longer exist will not be included.
func (mb mergeableBoundaries) containedAssets(mergedAssets []common.Asset, logger *slog.Logger) []string {
	logger.Debug("Merging contained assets")
	containedAssets := make([]string, 0)

	for _, boundary := range mb.bnd {
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
	return mergeComponentExtras(logger, mb.bnd, func(a common.TrustBoundary) map[string]any {
		return a.Extra
	})
}
