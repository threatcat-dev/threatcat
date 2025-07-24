package dockercompose

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// DockerComposeAnalyzer analyzes Docker Compose files
type DockerComposeAnalyzer struct {
	DockerComposeFilePath string
	logger                *slog.Logger
}

// NewDockerComposeAnalyzer creates a new instance of DockerComposeAnalyzer
func NewDockerComposeAnalyzer(dockerComposeFilePath string, logger *slog.Logger) *DockerComposeAnalyzer {
	return &DockerComposeAnalyzer{
		DockerComposeFilePath: dockerComposeFilePath,
		logger:                logger.With("package", "dockercompose", "component", "DockerComposeAnalyzer"),
	}
}

// Analyze analyzes the given Docker Compose project and returns a list of assets
func (a *DockerComposeAnalyzer) Analyze(proj *types.Project, imageMap DockerImageMap) (*common.ThreatModel, error) {
	if imageMap == nil {
		return nil, fmt.Errorf("no handler for the docker image analysis was given")
	}

	model := common.EmptyThreatModel()

	logger := a.logger.With("proj.Name", proj.Name)
	logger.Debug("Beginning docker compose analysis")

	// Iterate over each service in the Docker Compose project
	for _, service := range proj.Services {
		// Generate a unique ID for the asset by hashing the file path and service name
		idHash := generateIDHash(a.DockerComposeFilePath, service.Name)
		// Create a new asset with the generated ID and service name
		asset := common.Asset{
			ID:          idHash,
			DisplayName: service.Name,
			Type:        imageMap.determineAssetType(service.Image, a.logger),
			Source:      common.DataSourceDockerCompose,
			Extra:       map[string]any{},
		}
		logger.Debug("Created a new instance of Asset for docker compose service", "service.Name", service.Name, "asset", asset)
		// Add the asset to the list of assets
		model.Assets = append(model.Assets, asset)
	}

	logger.Debug("Docker compose analysis finished", "assetCount", len(model.Assets))

	// Return the list of assets
	return &model, nil
}

// generateIDHash generates a unique ID hash for a given file path and service name
func generateIDHash(filePath, serviceName string) string {
	hasher := sha256.New()
	hasher.Write([]byte(filePath + serviceName))
	return hex.EncodeToString(hasher.Sum(nil))[:common.MaxIDHashLength]
}
