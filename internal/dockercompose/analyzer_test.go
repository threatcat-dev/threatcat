package dockercompose

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"testing"

	"github.com/compose-spec/compose-go/v2/cli"
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

// TestGenerateIDHash tests the generateIDHash function to ensure it produces non-empty hashes and equal hashes for same input.
func TestGenerateIDHash(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		serviceName string
		expectedLen int
	}{
		{
			name:        "Valid file path and service name",
			filePath:    "/path/to/docker-compose.yml",
			serviceName: "web",
			expectedLen: common.MaxIDHashLength,
		},
		{
			name:        "Empty file path and service name",
			filePath:    "",
			serviceName: "",
			expectedLen: common.MaxIDHashLength,
		},
		{
			name:        "Long file path and service name",
			filePath:    "/a/very/long/path/to/a/docker-compose/file/that/should/be/hashed",
			serviceName: "very-long-service-name",
			expectedLen: common.MaxIDHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := generateIDHash(tt.filePath, tt.serviceName)
			secondHash := generateIDHash(tt.filePath, tt.serviceName) // Generate a second hash for comparison
			assert.Equal(t, hash, secondHash, "Hashes should be equal for the same input")
			assert.NotEmpty(t, hash, "Hash should not be empty")
			assert.Equal(t, tt.expectedLen, len(hash), fmt.Sprintf("Hash length should be %d characters", tt.expectedLen))
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
