// This file implements parsing and analysis of Threat Dragon JSON files into the internal threat model.

package threatdragon

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"github.com/threatcat-dev/threatcat/internal/common"
)

var (
	ErrDuplicateInternalID = errors.New("found a duplicate of an internal id")
)

// ThreatDragonAnalyzer analyzes Threat Dragon files
type ThreatDragonInput struct {
	filePath string
	logger   *slog.Logger
}

type analyzerHandlerData struct {
	internalID        string
	isGeneratedByUser bool
	assetThreats      []common.Threat
	threatModelMap    map[int]Threat
	diagramIdx        int
	cellIdx           int
}

type analyzerFunc func(*analyzerHandlerData, *Cell, *common.ThreatModel, *slog.Logger)

// NewThreatDragonInput creates a new ThreatDragonInput instance.
func NewThreatDragonInput(filePath string, logger *slog.Logger) *ThreatDragonInput {
	return &ThreatDragonInput{
		filePath: filePath,
		logger:   logger.With("package", "threatdragon", "component", "ThreatDragonInput", "filePath", filePath),
	}
}

// Analyze parses the Threat Dragon project file, iterates over diagrams and cells,
// and converts them into the internal common.ThreatModel representation.
func (i *ThreatDragonInput) Analyze() (*common.ThreatModel, error) {
	i.logger.Debug("Beginning ThreatDragon analysis")
	parsed := Project{}

	data, err := os.ReadFile(i.filePath)
	i.logger.Debug("Reading file")

	if err != nil {
		return nil, err
	}
	i.logger.Debug("Unmarshaling json")
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		return nil, err
	}
	model := common.EmptyThreatModel()

	//Add the whole project as extra data to the model
	model.Extra["ThreatDragonModel"] = parsed

	//If there are no Diagrams skip the analysis steps
	if len(parsed.Detail.Diagrams) == 0 {
		i.logger.Info("No Diagrams found to analyze")
		return &model, nil
	}

	//Register handler functions for specific cell types in the following loop
	handlers := map[string]analyzerFunc{
		cellTypeTrustBoundary: handlerCellTrustBoundaryAnalyze,
		cellTypeDataFlow:      handlerCellDataflowAnalyze,
		cellTypeDatabase:      handlerCellAssetAnalyze,
		cellTypeProcess:       handlerCellAssetAnalyze,
	}
	//Iterate over each diagram in the Threat Dragon project
	i.logger.Debug("Iterating over diagrams", "count", len(parsed.Detail.Diagrams))

	// Analyze only one Diagram since there is not enough information from other sources to modify more than one diagram
	diagramIdx := 0
	diagram := parsed.Detail.Diagrams[diagramIdx]

	logger := i.logger.With("diagram.ID", diagram.ID)
	//Iterate over each relevant cell in the diagram
	logger.Debug("Iterating over cells", "count", len(diagram.Cells))
	for k, cell := range diagram.Cells {
		logger := logger.With("cell.ID", cell.ID)

		handler, ok := handlers[cell.Data.Type]
		if !ok {
			logger.Debug("Cell type is not relevant. Continuing.", "cellType", cell.Data.Type)
			continue
		}

		//Check if the cell has an internal ID
		internalID := extractID(cell.Data.Description, i.logger)
		isGeneratedByUser := false

		//If the cell has no internal ID, generate one. This means the asset is created by the user
		if internalID == "" {
			isGeneratedByUser = true
			internalID = generateIDHash(i.filePath, cell.ID)
			logger.Debug("No stored threatcat ID found. This cell must be user created.", "generatedID", internalID)
		} else {
			logger.Debug("Stored threatcat ID found.", "id", internalID)
		}

		if checkForDuplicateID(&model, internalID, logger) {
			return nil, ErrDuplicateInternalID
		}

		//Create a new asset with the data of the cell
		assetThreats, threatModelMap := getCellDataThreats(cell.Data, i.logger, i.filePath)

		data := analyzerHandlerData{
			internalID:        internalID,
			isGeneratedByUser: isGeneratedByUser,
			assetThreats:      assetThreats,
			threatModelMap:    threatModelMap,
			diagramIdx:        diagramIdx,
			cellIdx:           k,
		}

		handler(&data, &cell, &model, logger)
	}

	//replace asset names with their IDs in dataflows to ensure to be unique
	replaceSourceTargetAssetIdsWithInternalIDs(model.DataFlows, diagram.Cells, i.filePath, i.logger)

	logger.Debug("Finished analysing diagram", "currentAssetCount", len(model.Assets))

	err = linkAssetsWithTrustboundaries(&model)
	if err != nil {
		return nil, err
	}

	i.logger.Debug("ThreatDragon Analysis finished", "assetCount", len(model.Assets))

	return &model, nil
}

// checkForDuplicateID checks if the id is already present in the model
func checkForDuplicateID(model *common.ThreatModel, id string, logger *slog.Logger) bool {
	idx := slices.IndexFunc(model.Assets, func(a common.Asset) bool {
		return a.ID == id
	})
	if idx != -1 {
		logger.Error("Found duplicate id", "asset", id)
		return true
	}
	idx = slices.IndexFunc(model.Boundaries, func(b common.TrustBoundary) bool {
		return b.ID == id
	})
	if idx != -1 {
		logger.Error("Found duplicate id", "boundary", id)
		return true
	}
	idx = slices.IndexFunc(model.DataFlows, func(d common.DataFlow) bool {
		return d.ID == id
	})
	if idx != -1 {
		logger.Error("Found duplicate id", "dataflow", id)
		return true
	}
	return false
}

// replaceSourceTargetAssetIdsWithInternalIDs updates data flow source and target IDs from Threat Dragon cell IDs to internal IDs.
func replaceSourceTargetAssetIdsWithInternalIDs(dataflows []common.DataFlow, cells []Cell, filePath string, logger *slog.Logger) {
	for i := range dataflows {
		if dataflows[i].TargetID != "" {
			internalID := findCorrespondingAsset(dataflows[i].TargetID, cells, filePath, logger)
			if internalID != "" {
				dataflows[i].TargetID = internalID
				logger.Debug("Found Target for dataFlow", "dataflow", dataflows[i].Name, "id", internalID)
			}
		}

		if dataflows[i].SourceID != "" {
			internalID := findCorrespondingAsset(dataflows[i].SourceID, cells, filePath, logger)
			if internalID != "" {
				dataflows[i].SourceID = internalID
				logger.Debug("Found Source for dataflow", "dataflow", dataflows[i].Name, "id", internalID)
			}
		}
	}
}

// findCorrespondingAsset searches for a cell by its Threat Dragon ID and returns its internal ID.
func findCorrespondingAsset(idToFind string, cells []Cell, filePath string, logger *slog.Logger) string {
	for _, c := range cells {
		if c.ID == idToFind {
			internalID := extractID(c.Data.Description, logger)
			if internalID == "" {
				internalID = generateIDHash(filePath, c.ID)
			}
			return internalID
		}
	}

	return ""
}

// getCellDataType determines the asset type based on the data type
func getCellDataType(data Data) common.AssetType {
	switch data.Type {
	//TODO: can further asset types be recognized?
	case cellTypeProcess:
		return common.AssetTypeApplication
	case cellTypeDatabase:
		return common.AssetTypeDatabase
	// At the moment assets in the internal model can only represent an process or a database
	case cellTypeActor:
		return common.AssetTypeUnknown
	case cellTypeDataFlow:
		return common.AssetTypeUnknown
	case cellTypeTrustBoundaryCurve:
		return common.AssetTypeUnknown
	default:
		return common.AssetTypeUnknown
	}
}

// getCellDataThreats extracts threats from the cell data
func getCellDataThreats(data Data, logger *slog.Logger, filePath string) ([]common.Threat, map[int]Threat) {
	threatModelThreats := make(map[int]Threat)
	threats := make([]common.Threat, 0)
	if data.Threats == nil {
		return threats, threatModelThreats
	}

	for idx, threat := range *data.Threats {

		internalID := extractID(&threat.Description, logger)
		isGeneratedByUser := false

		if internalID == "" {
			isGeneratedByUser = true
			internalID = generateIDHash(filePath, threat.ID)
			logger.Debug("No stored threatcat ID found. This threat must be user created.", "generatedID", internalID)
		} else {
			logger.Debug("Stored threatcat threat ID found.", "id", internalID)
		}

		// Store the original ThreatDragon threat in the map for reference
		threatModelThreats[idx] = threat

		// convert model.Nullable fields into plain values expected by common.Threat
		var num int64
		if threat.Number.Set && threat.Number.Present {
			num = threat.Number.Value
		} else {
			num = 0
		}

		var score string
		if threat.Score.Set && threat.Score.Present {
			score = threat.Score.Value
		} else {
			score = ""
		}

		threatType := common.ParseThreatType(threat.Type)
		modelType := common.ParseModelType(threat.ModelType)

		if modelType == common.NotSupported {
			logger.Debug("Threat has an unsupported model type. It will not be parsed into the internal model.")
			continue
		}

		threats = append(threats, common.Threat{
			InternalID:        internalID,
			ID:                threat.ID,
			Title:             threat.Title,
			Status:            common.ParseStatus(threat.Status),
			Severity:          threat.Severity,
			Type:              threatType,
			Description:       threat.Description,
			Mitigation:        threat.Mitigation,
			ModelType:         modelType,
			Number:            num,
			Score:             score,
			IsGeneratedByUser: isGeneratedByUser,
			Source:            common.DataSourceThreatDragon,
			MapIndex:          idx,
		})

	}
	return threats, threatModelThreats
}

// linkAssetsWithTrustboundaries determines which assets are located within which trust boundaries based on their positions.
func linkAssetsWithTrustboundaries(model *common.ThreatModel) error {
	modifiedBoundaries := []common.TrustBoundary{}

	for _, trustBoundary := range model.Boundaries {
		trustBoundaryRect, err := common.Get[*common.Rectangle](trustBoundary.Extra, "ThreatDragonPosition")
		if err != nil {
			return err
		}
		for i := range model.Assets {
			assetRect, err := common.Get[*common.Rectangle](model.Assets[i].Extra, "ThreatDragonPosition")
			if err != nil {
				return err
			}

			if trustBoundaryRect.Contains(assetRect) {
				memberOfTrustBoundaries, err := common.Get[[]string](model.Assets[i].Extra, "MemberOfTrustBoundaries")
				if err != nil {
					model.Assets[i].Extra["MemberOfTrustBoundaries"] = []string{trustBoundary.ID}
				} else {
					model.Assets[i].Extra["MemberOfTrustBoundaries"] = append(memberOfTrustBoundaries, trustBoundary.ID)
				}
				trustBoundary.ContainedAssets = append(trustBoundary.ContainedAssets, model.Assets[i].ID)
			}
		}
		modifiedBoundaries = append(modifiedBoundaries, trustBoundary)
	}
	model.Boundaries = modifiedBoundaries

	return nil
}

// Analyzer Function to handle a cell that is a generic asset
func handlerCellAssetAnalyze(data *analyzerHandlerData, cell *Cell, model *common.ThreatModel, logger *slog.Logger) {
	asset := common.Asset{
		ID:          data.internalID,
		DisplayName: common.PtrDeref(cell.Data.Name),
		Type:        getCellDataType(cell.Data),
		Threats:     data.assetThreats,
		Source:      common.DataSourceThreatDragon,
		Extra: map[string]any{
			"ThreatDragonDiagramCellIdx": fmt.Sprintf("%d-%d", data.diagramIdx, data.cellIdx),
			"IsGeneratedByUser":          data.isGeneratedByUser,
			"ThreatModelMap":             data.threatModelMap,
			"ThreatDragonPosition": common.NewRectangle(
				common.PtrDeref(cell.Position).X,
				common.PtrDeref(cell.Position).Y,
				common.PtrDeref(cell.Size).Width,
				common.PtrDeref(cell.Size).Height,
			),
		},
	}

	logger.Debug("Created a new instance of Asset for ThreatDragon cell", "asset", asset)

	//add the asset to the model
	model.Assets = append(model.Assets, asset)
}

// Analyzer Function to handle a cell that is a dataflow
func handlerCellDataflowAnalyze(data *analyzerHandlerData, cell *Cell, model *common.ThreatModel, logger *slog.Logger) {
	name := common.PtrDerefOr(cell.Data.Name, "")
	proto := common.PtrDerefOr(cell.Data.Protocol, "")
	encrypted := common.PtrDerefOr(cell.Data.IsEncrypted, false)
	publicNet := common.PtrDerefOr(cell.Data.IsPublicNetwork, false)
	bidirectional := common.PtrDerefOr(cell.Data.IsBidirectional, false)

	src := ""
	if cell.Source != nil {
		src = common.PtrDerefOr(cell.Source.Cell, "")
	}
	tgt := ""
	if cell.Target != nil {
		tgt = common.PtrDerefOr(cell.Target.Cell, "")
	}

	dataFlow := common.DataFlow{
		ID:                data.internalID,
		Name:              name,
		Protocol:          proto,
		Encrypted:         encrypted,
		PublicNetwork:     publicNet,
		SourceID:          src,
		TargetID:          tgt,
		Bidirectional:     bidirectional,
		Threats:           data.assetThreats,
		DataSource:        common.DataSourceThreatDragon,
		IsGeneratedByUser: data.isGeneratedByUser,
		Extra: map[string]any{
			"ThreatModelMap":             data.threatModelMap,
			"ThreatDragonDiagramCellIdx": fmt.Sprintf("%d-%d", data.diagramIdx, data.cellIdx),
		},
	}

	model.DataFlows = append(model.DataFlows, dataFlow)
}

// Analyzer Function to handle a cell that is a trustboundary
func handlerCellTrustBoundaryAnalyze(data *analyzerHandlerData, cell *Cell, model *common.ThreatModel, logger *slog.Logger) {
	trustBoudary := common.TrustBoundary{
		ID:              data.internalID,
		DisplayName:     common.PtrDeref(cell.Data.Name),
		ContainedAssets: []string{},
		Source:          common.DataSourceThreatDragon,
		Extra: map[string]any{
			"ThreatDragonDiagramCellIdx": fmt.Sprintf("%d-%d", data.diagramIdx, data.cellIdx),
			"IsGeneratedByUser":          data.isGeneratedByUser,
			"ThreatModelMap":             data.threatModelMap,
			"ThreatDragonPosition": common.NewRectangle(
				cell.Position.X,
				cell.Position.Y,
				cell.Size.Width,
				cell.Size.Height,
			),
		},
	}

	model.Boundaries = append(model.Boundaries, trustBoudary)
}
