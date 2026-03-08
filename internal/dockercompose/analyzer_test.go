package dockercompose

import (
	"context"
	"log/slog"
	"sort"
	"testing"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// List of test assets found in the docker-compose-for-test.yml file
var testAssets = []common.Asset{
	{ID: "hash", DisplayName: "db", Type: common.AssetTypeDatabase, Extra: map[string]any{}},
	{ID: "hash", DisplayName: "db2", Type: common.AssetTypeDatabase, Extra: map[string]any{}},
	{ID: "hash", DisplayName: "web", Type: common.AssetTypeWebserver, Extra: map[string]any{}},
}

// TestAnalyzer tests the Analyze method of DockerComposeAnalyzer
func TestAnalyzer(t *testing.T) {
	// Create a new DockerImageMap instance
	// This should be initialized with the internal image map
	dockerImageMap, err := NewDockerImageMap("")
	assert.NoError(t, err)

	// Sort the testAssets slice by the DisplayName field for comparison with later results
	sort.Slice(testAssets, func(i, j int) bool {
		return testAssets[i].DisplayName < testAssets[j].DisplayName
	})

	tests := []struct {
		name     string
		filePath string
		expected []common.Asset
	}{
		{
			"asset generation test",
			"testdata/docker-compose-for-test.yml",
			testAssets,
		},
	}

	// Iterate over each test case
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectName := "test_project"

			// Create project options from the docker-compose file
			options, err := cli.NewProjectOptions(
				[]string{tt.filePath},
				cli.WithOsEnv,
				cli.WithDotEnv,
				cli.WithName(projectName),
			)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Create a project from the options
			project, err := options.LoadProject(context.TODO())
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Create a new DockerComposeAnalyzer and analyze the project
			analyzer := NewDockerComposeAnalyzer(tt.filePath, slog.Default())
			result, err := analyzer.Analyze(project, dockerImageMap)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Sort the result slice by the DisplayName field
			sort.Slice(result.Assets, func(i, j int) bool {
				return result.Assets[i].DisplayName < result.Assets[j].DisplayName
			})

			// Compare the result with the expected assets
			for i, asset := range result.Assets {
				// Do not check ID because it is hashed
				assert.Equal(t, tt.expected[i].DisplayName, asset.DisplayName)
				assert.Equal(t, tt.expected[i].Type, asset.Type)
				assert.Equal(t, tt.expected[i].Extra, asset.Extra)
			}
		})
	}
}

// TestDetermineAssetType tests the determineAssetType function
func TestDetermineAssetType(t *testing.T) {
	// Create a new DockerImageMap instance
	// This should be initialized with the internal image map
	dockerImageMap, err := NewDockerImageMap("")
	assert.NoError(t, err)

	tests := []struct {
		image    string
		expected common.AssetType
	}{
		{"myregistry.com/myrepo/vitess/lite:1.1", common.AssetTypeApplication},
		{"postgres:latest", common.AssetTypeDatabase},
		{"mongo:4.2", common.AssetTypeDatabase},
		{"mysql:5.7", common.AssetTypeDatabase},
		{"mariadb:latest", common.AssetTypeDatabase},
		{"influxdb:7.8", common.AssetTypeDatabase},
		{"neo4j:10.15", common.AssetTypeDatabase},
		{"percona:latest", common.AssetTypeDatabase},
		{"couchdb:14.07", common.AssetTypeDatabase},

		{"nginx:alpine", common.AssetTypeWebserver},
		{"httpd:2.4", common.AssetTypeWebserver},
		{"myregistry.com/myrepo/nginx:latest", common.AssetTypeWebserver},
		{"haproxy", common.AssetTypeWebserver},
		{"tomcat", common.AssetTypeWebserver},
		{"caddy", common.AssetTypeWebserver},
		{"jetty", common.AssetTypeWebserver},
		{"tomee", common.AssetTypeWebserver},
		{"watchtower", common.AssetTypeInfrastructure},
		{"ubuntu", common.AssetTypeUnknown},
		{"docker.hub/postgres:latest", common.AssetTypeDatabase},
		{"unknown:latest", common.AssetTypeUnknown},
		{"rocket.chat", common.AssetTypeApplication},
	}

	// Iterate over each test case
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			result := dockerImageMap.determineAssetType(tt.image, slog.Default())
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGetImageName tests the getImageName function
func TestGetImageName(t *testing.T) {
	tests := []struct {
		image    string
		expected string
	}{
		{"postgres:latest", "postgres"},
		{"mongo:4.2", "mongo"},
		{"mysql:5.7", "mysql"},
		{"nginx:alpine", "nginx"},
		{"httpd:2.4", "httpd"},
		{"myregistry.com/myrepo/nginx:latest", "nginx"},
		{"docker.hub/postgres:latest", "postgres"},
		{"unknown:latest", "unknown"},
		{"simpleimage", "simpleimage"},
		{"", ""},
		{"myregistry.com/myrepo/compleximage:1.0", "compleximage"},
		{"my-reg:5000/app:v1.0", "app"},
		{"ubuntu@sha256:abcdef1234567890", "ubuntu"},
		{"registry.gitlab.com/group/subgroup/image:tag", "image"},
	}

	// Iterate over each test case
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			result := getImageName(tt.image)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRemoveVersion(t *testing.T) {

	tests := []struct {
		image    string
		expected string
	}{
		{"postgres:latest", "postgres"},
		{"mongo:4.2", "mongo"},
		{"mysql:5.7", "mysql"},
		{"nginx:alpine", "nginx"},
		{"httpd:2.4", "httpd"},
		{"myregistry.com/myrepo/nginx:latest", "myregistry.com/myrepo/nginx"},
		{"docker.hub/postgres:latest", "docker.hub/postgres"},
		{"unknown:latest", "unknown"},
	}

	// Iterate over each test case
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			result := removeVersion(tt.image)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetermineAssetTypeWithNoDockerImageMap(t *testing.T) {
	// Create a new DockerComposeAnalyzer instance without a DockerImageMap
	analyzer := NewDockerComposeAnalyzer("testdata/docker-compose-for-test.yml", slog.Default())

	// Analyze the project without a DockerImageMap
	_, err := analyzer.Analyze(nil, nil)
	assert.Error(t, err, "Expected an error when DockerImageMap is nil")
}

// TestAnalyzerBoundaries tests the Analyze method of DockerComposeAnalyzer for correct boundary creation
func TestAnalyzerBoundaries(t *testing.T) {

	dockerComposeFilePath := "testdata/docker-compose-for-test.yml"
	// Create a new DockerImageMap instance
	// This should be initialized with the internal image map
	dockerImageMap, err := NewDockerImageMap("")
	assert.NoError(t, err)

	tests := []struct {
		name     string
		proj     *types.Project
		expected []common.TrustBoundary
	}{
		{
			"Test single network boundary creation",
			&types.Project{
				Name: "myapp",
				Networks: types.Networks{
					"frontend": {Name: "myapp_frontend"},
				},
				Services: types.Services{
					"web": {
						Name: "web",
						Networks: map[string]*types.ServiceNetworkConfig{
							"frontend": {},
						},
					},
				},
			},
			append([]common.TrustBoundary{},
				common.TrustBoundary{
					ID:          common.GenerateIDHashFromFilePath(dockerComposeFilePath, "myapp_frontend"),
					DisplayName: "frontend",
					Source:      common.DataSourceDockerCompose,
					Extra: map[string]any{
						"initial-description": "Docker compose network",
					},
					ContainedAssets: []string{common.GenerateIDHashFromFilePath(dockerComposeFilePath, "web")},
				}),
		},
		{
			"Test no network creates default boundary",
			&types.Project{
				Name:     "myapp",
				Networks: types.Networks{},
				Services: types.Services{
					"web": {
						Name:     "web",
						Networks: map[string]*types.ServiceNetworkConfig{},
					},
				},
			},
			append([]common.TrustBoundary{},
				common.TrustBoundary{
					ID:          common.GenerateIDHashFromFilePath(dockerComposeFilePath, "default"),
					DisplayName: "Default Network",
					Source:      common.DataSourceDockerCompose,
					Extra: map[string]any{
						"initial-description": "General trust boundary for docker compose file 'testdata/docker-compose-for-test.yml'",
					},
					ContainedAssets: []string{common.GenerateIDHashFromFilePath(dockerComposeFilePath, "web")},
				},
			),
		},
		{
			"Test multiple networks and display name computation",
			&types.Project{
				Name: "myapp",
				Networks: types.Networks{
					"frontend": {Name: "myapp_frontend"},
					"backend":  {Name: "myapp_backend"},
				},
				Services: types.Services{
					"proxy": {
						Name: "proxy",
						Networks: map[string]*types.ServiceNetworkConfig{
							"frontend": {},
						},
					},
				},
			},
			append([]common.TrustBoundary{},
				common.TrustBoundary{
					ID:          common.GenerateIDHashFromFilePath(dockerComposeFilePath, "myapp_frontend"),
					DisplayName: "frontend",
					Source:      common.DataSourceDockerCompose,
					Extra: map[string]any{
						"initial-description": "Docker compose network",
					},
					ContainedAssets: []string{common.GenerateIDHashFromFilePath(dockerComposeFilePath, "proxy")},
				},
				common.TrustBoundary{
					ID:          common.GenerateIDHashFromFilePath(dockerComposeFilePath, "myapp_backend"),
					DisplayName: "backend",
					Source:      common.DataSourceDockerCompose,
					Extra: map[string]any{
						"initial-description": "Docker compose network",
					},
				},
			),
		},
		{
			"Test network name prefix handling",
			&types.Project{
				Name: "myapp",
				Networks: types.Networks{
					"frontend": {Name: "myapp_frontend"},
				},
				Services: types.Services{
					"web": {
						Name: "web",
						Networks: map[string]*types.ServiceNetworkConfig{
							"frontend": {},
						},
					},
				},
			},
			append([]common.TrustBoundary{},
				common.TrustBoundary{
					ID:          common.GenerateIDHashFromFilePath(dockerComposeFilePath, "myapp_frontend"),
					DisplayName: "frontend",
					Source:      common.DataSourceDockerCompose,
					Extra: map[string]any{
						"initial-description": "Docker compose network",
					},
					ContainedAssets: []string{common.GenerateIDHashFromFilePath(dockerComposeFilePath, "web")},
				},
			),
		},
	}

	// Iterate over each test case
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new DockerComposeAnalyzer and analyze the project
			analyzer := NewDockerComposeAnalyzer(dockerComposeFilePath, slog.Default())
			result, err := analyzer.Analyze(tt.proj, dockerImageMap)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}
			assert.ElementsMatch(t, tt.expected, result.Boundaries)
		})
	}
}
