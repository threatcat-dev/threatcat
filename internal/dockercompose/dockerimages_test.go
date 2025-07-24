package dockercompose

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// TestNewDockerImageMap checks that the handler is initialized with the internal image map.
// It should contain some predefined images and their asset types.
// This test ensures that the DockerImageMap is correctly set up with the internal image map.
func TestNewDockerImageMap(t *testing.T) {
	tests := []struct {
		name         string
		image        string
		expectedType common.AssetType
	}{
		{"Grafana is application", "grafana", common.AssetTypeApplication},
		{"Postgres is database", "postgres", common.AssetTypeDatabase},
		{"Nginx is webserver", "nginx", common.AssetTypeWebserver},
		{"Busybox is unknown", "busybox", common.AssetTypeUnknown},
	}

	imageMap, err := NewDockerImageMap("")
	assert.NoError(t, err)
	assert.NotNil(t, imageMap)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedType, imageMap[tc.image])
		})
	}
}

// TestMergeDockerImageMaps checks merging of external image maps.
// It should add new entries or overwrite existing ones in the handler's map as expected.
func TestMergeDockerImageMaps(t *testing.T) {
	tests := []struct {
		name           string
		external       map[string]common.AssetType
		expectedResult map[string]common.AssetType
	}{
		{
			name: "Add new custom app",
			external: map[string]common.AssetType{
				"customapp": common.AssetTypeApplication,
			},
			expectedResult: map[string]common.AssetType{
				"customapp": common.AssetTypeApplication,
			},
		},
		{
			name: "Overwrite existing",
			external: map[string]common.AssetType{
				"grafana": common.AssetTypeWebserver,
			},
			expectedResult: map[string]common.AssetType{
				"grafana": common.AssetTypeWebserver, // Should be overwritten
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := NewDockerImageMap("")
			assert.NoError(t, err)
			err = mergeDockerImageMaps(handler, tc.external)
			assert.NoError(t, err)
			for image, expectedType := range tc.expectedResult {
				got, ok := handler[image]
				assert.True(t, ok, "Image %s should exist in map", image)
				assert.Equal(t, expectedType, got)
			}
		})
	}
}

// TestMergeDockerImageMaps_Nil checks error on nil maps.
func TestMergeDockerImageMaps_Nil(t *testing.T) {
	err := mergeDockerImageMaps(nil, map[string]common.AssetType{})
	assert.Error(t, err)
	err = mergeDockerImageMaps(map[string]common.AssetType{}, nil)
	assert.Error(t, err)
	err = mergeDockerImageMaps(nil, nil)
	assert.Error(t, err)
}

// TestReadConfig checks reading a YAML config file.
func TestReadConfig(t *testing.T) {
	config, err := readConfig("testdata/dockerimage.config")
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.ElementsMatch(t, []string{"myapp1", "myapp2"}, config.Applications)
	assert.ElementsMatch(t, []string{"mydb"}, config.Databases)
	assert.ElementsMatch(t, []string{"myweb"}, config.Webservers)
	assert.ElementsMatch(t, []string{"myinfra"}, config.Infrastructure)
}

// TestReadConfigFile checks reading a YAML config file and parsing its sections correctly.
func TestReadConfigFile(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expected    map[string]common.AssetType
	}{
		{
			name: "All types",
			yamlContent: `
applications:
  - myapp1
  - myapp2
databases:
  - mydb
webservers:
  - myweb
infrastructure:
  - myinfra
`,
			expected: map[string]common.AssetType{
				"myapp1":  common.AssetTypeApplication,
				"myapp2":  common.AssetTypeApplication,
				"mydb":    common.AssetTypeDatabase,
				"myweb":   common.AssetTypeWebserver,
				"myinfra": common.AssetTypeInfrastructure,
			},
		},
		{
			name: "Only infrastructure",
			yamlContent: `
infrastructure:
  - infraonly
`,
			expected: map[string]common.AssetType{
				"infraonly": common.AssetTypeInfrastructure,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "docker_image_map_*.yaml")
			assert.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tc.yamlContent)
			assert.NoError(t, err)
			tmpFile.Close()

			imageMap, err := readDockerImageMapConfig(tmpFile.Name())
			assert.NoError(t, err)
			for image, assetType := range tc.expected {
				got, ok := imageMap[image]
				assert.True(t, ok, "Image %s should exist in map", image)
				assert.Equal(t, assetType, got)
			}
		})
	}
}
