// Package dockercompose provides functionality for analyzing Docker Compose files
// to generate security threat models. It parses compose files, identifies assets and
// trust boundaries, and investigates potential security threats using STRIDE methodology.

// This file implements functionality for parsing Docker Compose YAML files to create a structured representation of the project.

package dockercompose

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
)

// DockerComposeAnalyzer analyzes Docker Compose files
type DockerComposeParser struct {
	filePath string
	logger   *slog.Logger
}

// NewDockerComposeParser creates a new instance of DockerComposeParser
func NewDockerComposeParser(filePath string, logger *slog.Logger) *DockerComposeParser {
	return &DockerComposeParser{
		filePath: filePath,
		logger:   logger.With("package", "dockercompose", "component", "DockerComposeParser"),
	}
}

// extracts filepath and sanitizes it to create an usable project namen
func (p *DockerComposeParser) createProjectNameOutOfFilepath(filePath string) string {
	//extract filename, replace "-" characters with "_"
	projectName := strings.ReplaceAll(strings.ToLower(strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filepath.Base(filePath)))), "-", "_")
	// Define a regular expression that matches any character that is NOT a-z, A-Z, 0-9, hyphen, or underscore.
	re := regexp.MustCompile(`[^a-zA-Z0-9-_]`)

	// Eliminate all unsupported characters by replacing them with an empty string.
	sanitizedProjName := re.ReplaceAllString(projectName, "")
	p.logger.Info("Generated project name", "ProjectName", sanitizedProjName)
	return sanitizedProjName
}

/* Brief: Parses a docker Compose YAML
 * Returns: Pointer to Project on success, nil on failure
 */
func (p *DockerComposeParser) ParseDockerComposeYML() (*types.Project, error) {
	//convert File Path to projectName
	projectName := p.createProjectNameOutOfFilepath(p.filePath)
	logger := p.logger.With("projectName", projectName)
	// Create project options from the docker-compose file
	options, err := cli.NewProjectOptions(
		[]string{p.filePath},
		cli.WithOsEnv,
		cli.WithDotEnv,
		cli.WithName(projectName),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create project options: %w", err)
	}
	logger.Debug("Attempting to load the project")
	// Create a project from the options
	project, err := options.LoadProject(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load compose project: %w", err)
	}
	logger.Info("Successfully parsed input yml")
	return project, nil
}
