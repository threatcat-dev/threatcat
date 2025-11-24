package threatdragon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"

	"github.com/threatcat-dev/threatcat/internal/common"
)

// ThreatDragonAnalyzer analyzes Threat Dragon files
type ThreatDragonInput struct {
	filePath string
	logger   *slog.Logger
}

// NewThreatDragoIinput creates a new ThreatDragonInput instance
func NewThreatDragonInput(filePath string, logger *slog.Logger) *ThreatDragonInput {
	return &ThreatDragonInput{
		filePath: filePath,
		logger:   logger.With("package", "threatdragon", "component", "ThreatDragonInput", "filePath", filePath),
	}
}

// Analyze analyzes the given Threat Dragon project and returns a list of assets
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

	//Iterate over each diagram in the Threat Dragon project
	i.logger.Debug("Iterating over diagrams", "count", len(parsed.Detail.Diagrams))
	for j, diagram := range parsed.Detail.Diagrams {
		logger := i.logger.With("diagram.ID", diagram.ID)
		//Iterate over each relevant cell in the diagram
		logger.Debug("Iterating over cells", "count", len(diagram.Cells))
		for k, cell := range diagram.Cells {
			logger := logger.With("cell.ID", cell.ID)
			//Check if the cell is relevant for analysis
			if !isRelevantType(cell.Data.Type) {
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

			if isCellTrustBoudary(&cell) {
				trustBoudary := common.TrustBoundary{
					ID:              internalID,
					DisplayName:     *cell.Data.Name,
					ContainedAssets: []string{},
					Source:          common.DataSourceThreatDragon,
					Extra: map[string]any{
						"ThreatDragonPosition": common.NewRectangle(
							cell.Position.X,
							cell.Position.Y,
							cell.Size.Width,
							cell.Size.Height,
						),
					},
				}

				model.Boundaries = append(model.Boundaries, trustBoudary)

				continue
			}

			//Create a new asset with the data of the cell
			assetThreats, threatModelMap := getCellDataThreats(cell.Data, i.logger, i.filePath)

			asset := common.Asset{
				ID:          internalID,
				DisplayName: *cell.Data.Name,
				Type:        getCellDataType(cell.Data),
				Threats:     assetThreats,
				Source:      common.DataSourceThreatDragon,
				Extra: map[string]any{
					"ThreatDragonDiagramCellIdx": fmt.Sprintf("%d-%d", j, k),
					"IsGeneratedByUser":          isGeneratedByUser,
					"ThreatModelMap":             threatModelMap,
					"ThreatDragonPosition": common.NewRectangle(
						cell.Position.X,
						cell.Position.Y,
						cell.Size.Width,
						cell.Size.Height,
					),
				},
			}

			logger.Debug("Created a new instance of Asset for ThreatDragon cell", "asset", asset)

			//add the asset to the model
			model.Assets = append(model.Assets, asset)
		}
		logger.Debug("Finished analysing diagram", "currentAssetCount", len(model.Assets))
	}

	for _, trustBoundary := range model.Boundaries {
		trustBoundaryRect, err := common.Get[common.Rectangle](trustBoundary.Extra, "ThreatDragonPosition")
		if err != nil {
			return nil, err
		}
		for _, asset := range model.Assets {
			assetRect, err := common.Get[common.Rectangle](asset.Extra, "ThreatDragonPosition")
			if err != nil {
				return nil, err
			}

			if trustBoundaryRect.IsContained(&assetRect) {
				trustBoundary.ContainedAssets = append(trustBoundary.ContainedAssets, asset.ID)
			}
		}
	}

	i.logger.Debug("ThreatDragon Analysis finished", "assetCount", len(model.Assets))

	return &model, nil
}

// isRelevantType checks if the cell type is relevant for analysis
func isRelevantType(cellType string) bool {
	return cellType == "tm.Store" || cellType == "tm.Process"
}

// getCellDataType determines the asset type based on the data type
func getCellDataType(data Data) common.AssetType {
	switch data.Type {
	//TODO: can further asset types be recognized?
	case "tm.Process":
		return common.AssetTypeApplication
	case "tm.Store":
		return common.AssetTypeDatabase
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

		threatType := common.ThreatThreatType(threat.Type)
		modelType := common.ThreatModelType(threat.ModelType)

		if modelType == common.NotSupported {
			logger.Debug("Threat has an unsupported model type. It will not be parsed into the internal model.")
			continue
		}

		threats = append(threats, common.Threat{
			InternalID:        internalID,
			ID:                threat.ID,
			Title:             threat.Title,
			Status:            common.ThreatStatus(threat.Status),
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

// generateIDHash generates a unique ID hash for a given file path and data description
func generateIDHash(filePath, thretdragonCellID string) string {
	hasher := sha256.New()
	hasher.Write([]byte(filePath + thretdragonCellID))
	return hex.EncodeToString(hasher.Sum(nil))[:common.MaxIDHashLength]
}

func generateInternalIDWithTag(filePath string, thretdragonCellID string, logger *slog.Logger) (idWithTag string, id string) {
	//Generate a unique ID hash for the cell
	id = generateIDHash(filePath, thretdragonCellID)
	logger.Debug("Generated id for Cell", "ID", id, "thretdragonCellID", thretdragonCellID)
	idWithTag = "#AnalyzerID:" + id + "#"
	return idWithTag, id
}

func analyzerIDTag(id string) string {
	return fmt.Sprintf("#AnalyzerID:%s#", id)
}

// extractID extracts the internal ID from the cell description
func extractID(description *string, logger *slog.Logger) string {
	logger.Debug("Extracting description and looking for ID")
	if description == nil {
		return ""
	}
	pattern := fmt.Sprintf(`#AnalyzerID:([0-9a-fA-F]{%d})#`, common.MaxIDHashLength)
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(*description)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// isCellTrustBoudary determines if the analyzed cell is a tust boundary
// This is a extra function and not contained in getCellDataType because the datamodel sees TrustBoundaries as not a type of asset.
// Therefor handling this in getCellDataType would mix things that do not belong together
func isCellTrustBoudary(cell *Cell) bool {
	return cell.Data.Type == "tm.BoundaryBox"
}
