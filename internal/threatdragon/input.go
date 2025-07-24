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

			//Create a new asset with the data of the cell
			asset := common.Asset{
				ID:          internalID,
				DisplayName: *cell.Data.Name,
				Type:        getCellDataType(cell.Data),
				Source:      common.DataSourceThreatDragon,
				Extra: map[string]any{
					"ThreatDragonDiagramCellIdx": fmt.Sprintf("%d-%d", j, k),
					"IsGeneratedByUser":          isGeneratedByUser,
				},
			}

			logger.Debug("Created a new instance of Asset for ThreatDragon cell", "asset", asset)

			//add the asset to the model
			model.Assets = append(model.Assets, asset)
		}
		logger.Debug("Finished analysing diagram", "currentAssetCount", len(model.Assets))
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
