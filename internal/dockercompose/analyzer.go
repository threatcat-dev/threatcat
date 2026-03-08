// This file implements functionality for converting Docker Compose projects into threat model assets and boundaries.

package dockercompose

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// DockerComposeAnalyzer analyzes Docker Compose files
type DockerComposeAnalyzer struct {
	DockerComposeFilePath string
	threatInvestigator    *DockerComposeThreatInvestigator
	logger                *slog.Logger
}

// NewDockerComposeAnalyzer creates a new instance of DockerComposeAnalyzer for the given compose file and logger
func NewDockerComposeAnalyzer(dockerComposeFilePath string, logger *slog.Logger) *DockerComposeAnalyzer {
	return &DockerComposeAnalyzer{
		DockerComposeFilePath: dockerComposeFilePath,
		threatInvestigator:    NewDockerComposeThreatInvestigator(logger),
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

	networkNamePrefix := proj.Name + "_"

	for _, network := range proj.Networks {
		model.Boundaries = append(model.Boundaries, common.TrustBoundary{
			ID:          common.GenerateIDHashFromFilePath(a.DockerComposeFilePath, network.Name),
			DisplayName: strings.TrimPrefix(network.Name, networkNamePrefix),
			Source:      common.DataSourceDockerCompose,
			Extra: map[string]any{
				"initial-description": "Docker compose network",
			},
		})
	}

	assetIDs := make([]string, 0, len(proj.Services))

	// Iterate over each service in the Docker Compose project
	for _, service := range proj.Services {
		// Generate a unique ID for the asset by hashing the file path and service name
		idHash := common.GenerateIDHashFromFilePath(a.DockerComposeFilePath, service.Name)
		assetIDs = append(assetIDs, idHash)
		// Create a new asset with the generated ID and service name
		asset := common.Asset{
			ID:          idHash,
			DisplayName: service.Name,
			Type:        imageMap.determineAssetType(service.Image, a.logger),
			Threats:     a.threatInvestigator.InvestigateForThreats(service),
			Source:      common.DataSourceDockerCompose,
			Extra:       map[string]any{},
		}
		logger.Debug("Created a new instance of Asset for docker compose service", "service.Name", service.Name, "asset", asset)
		// Add the asset to the list of assets
		model.Assets = append(model.Assets, asset)

		for networkName := range service.Networks {
			index := slices.IndexFunc(model.Boundaries, func(b common.TrustBoundary) bool {
				return b.DisplayName == networkName
			})

			if index >= 0 {
				model.Boundaries[index].ContainedAssets = append(model.Boundaries[index].ContainedAssets, idHash)
			}
		}

	}

	if len(proj.Networks) == 0 {
		model.Boundaries = append(model.Boundaries, common.TrustBoundary{
			ID:          common.GenerateIDHashFromFilePath(a.DockerComposeFilePath, "default"),
			DisplayName: "Default Network",
			Source:      common.DataSourceDockerCompose,
			Extra: map[string]any{
				"initial-description": fmt.Sprintf("General trust boundary for docker compose file '%s'", a.DockerComposeFilePath),
			},
			ContainedAssets: assetIDs,
		})
	}

	logger.Debug("Docker compose analysis finished", "assetCount", len(model.Assets))

	// Return the list of assets
	return &model, nil
}
