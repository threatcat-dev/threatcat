package dockercompose

import (
	"log/slog"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper that calls parser with specified PATH
// Note: ensures DRY principle
func testParserWithPath(t *testing.T, filePath string, isNegativeTest bool) *types.Project {

	dcpParser := NewDockerComposeParser(filePath, slog.Default())
	project, err := dcpParser.ParseDockerComposeYML()

	if isNegativeTest {
		assert.Error(t, err)
		assert.Nil(t, project)
	} else {
		require.NoError(t, err)
		assert.NotNil(t, project)
	}

	return project
}

// Helper to test project name generation out of paths
// Note: ensures DRY principle
func testProjectNameCreationFileWithPath(t *testing.T, filePath string, expectedName string) {
	dcpParser := NewDockerComposeParser(filePath, slog.Default())
	projName := dcpParser.createProjectNameOutOfFilepath(filePath)
	assert.Equal(t, projName, expectedName)
}

// Confirm valid docker-compose File can be parsed
func TestParser_ParseValidYAML(t *testing.T) {
	// call parser with valid yaml
	testParserWithPath(t, "testdata/docker-compose-for-test.yml", false)
}

// Confirm parser rejects empty path
func TestParser_EmptyPathWillFail(t *testing.T) {
	// call parser with empty filepath
	testParserWithPath(t, "", true)
}

// Confirm parser rejects non YAML/YML path with existing file
func TestParser_PathToNonYamlWillFail(t *testing.T) {
	// call parser xml file
	testParserWithPath(t, "testdata/test.xml", true)
}

// Confirm parser rejects non existing yaml files
func TestParser_PathToNonExistingYamlWillFail(t *testing.T) {
	//call parser with non existing yaml
	testParserWithPath(t, "non_existing_file.yml", true)
}

// Test project name generation with valid file path (no unsupported characters)
func TestParser_TestProjectNameCreationValid(t *testing.T) {
	testProjectNameCreationFileWithPath(t, "example/directory/docker-compose.yml", "docker_compose")
}

// Test project name generation with unsupported characters are wiped from referenced path
func TestParser_TestProjectNameCreationWithUnsupportedCharacters(t *testing.T) {
	testProjectNameCreationFileWithPath(t, "example/directory/docker²³§-compose=?)($%!.yml", "docker_compose")
}
