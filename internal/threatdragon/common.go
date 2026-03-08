// This file implements shared helper functions used across the threatdragon package.

package threatdragon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/threatcat-dev/threatcat/internal/common"
)

// isCurve checks if the cell is a curve (data flow or boundary curve)
func isCurve(cell Cell) bool {
	return cell.Data.Type == cellTypeDataFlow || cell.Data.Type == cellTypeTrustBoundaryCurve
}

// generateIDHash generates a unique ID hash for a given file path and data description
func generateIDHash(filePath, threatdragonCellID string) string {
	hasher := sha256.New()
	hasher.Write([]byte(filePath + threatdragonCellID))
	return hex.EncodeToString(hasher.Sum(nil))[:common.MaxIDHashLength]
}

// analyzerIDTag returns a formatted tag string containing the provided ID, used to identify cells in Threat Dragon descriptions.
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
