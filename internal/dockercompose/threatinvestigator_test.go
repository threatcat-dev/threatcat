package dockercompose

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// TestInvestigateForThreats tests the InvestigateForThreats function
func TestInvestigateForThreats(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name            string
		service         types.ServiceConfig
		expectingThreat bool
	}{
		{
			name: "service without image",
			service: types.ServiceConfig{
				Name: "test_service",
				User: "User123",
				Deploy: &types.DeployConfig{
					Resources: types.Resources{
						Limits: &types.Resource{
							MemoryBytes: 512 * 1024 * 1024,
							NanoCPUs:    1 * 1e9,
						},
					},
				},
				Logging: &types.LoggingConfig{
					Driver: "json-file",
				},
			},
			expectingThreat: false,
		},
		{
			name: "image with specific version tag",
			service: types.ServiceConfig{
				Name:  "test_service",
				User:  "User123",
				Image: "nginx:1.21.0",
				Deploy: &types.DeployConfig{
					Resources: types.Resources{
						Limits: &types.Resource{
							MemoryBytes: 512 * 1024 * 1024,
							NanoCPUs:    1 * 1e9,
						},
					},
				},
				Logging: &types.LoggingConfig{
					Driver: "json-file",
				},
			},
			expectingThreat: true,
		},
		{
			name: "image without version tag",
			service: types.ServiceConfig{
				Name:  "test_service",
				User:  "User123",
				Image: "nginx",
				Deploy: &types.DeployConfig{
					Resources: types.Resources{
						Limits: &types.Resource{
							MemoryBytes: 512 * 1024 * 1024,
							NanoCPUs:    1 * 1e9,
						},
					},
				},
			},
			expectingThreat: true,
		},
		{
			name: "image with 'latest' tag in lowercase",
			service: types.ServiceConfig{
				Name:  "test_service",
				Image: "nginx:latest",
				Deploy: &types.DeployConfig{
					Resources: types.Resources{
						Limits: &types.Resource{
							MemoryBytes: 512 * 1024 * 1024,
							NanoCPUs:    1 * 1e9,
						},
					},
				},
			},
			expectingThreat: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.InvestigateForThreats(tt.service)
			if tt.expectingThreat {
				assert.Greater(t, len(threats), 0, "Expected at least one threat but got none")
			} else {
				assert.Equal(t, 0, len(threats), "Expected no threats but got some")
			}
		})
	}
}

// TestCheckForBindMounts tests the checkForBindMounts function
func TestCheckForBindMounts(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without volumes",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 0,
		},
		{
			name: "service with volume but not a bind mount",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "my_data_volume",
						Target: "/data",
						Type:   "volume",
					},
				},
			},
			expectingThreats: 0,
		},
		{
			name: "service with bind mount volume",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "/var/log/myapp:/logs",
						Target: "/logs",
						Type:   "bind",
					},
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with bind mount volume using Bind field",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "/etc/config:/config",
						Target: "/config",
						Bind:   &types.ServiceVolumeBind{},
					},
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with host path volume without type",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "./data:/app/data",
						Target: "/app/data",
						Type:   "",
					},
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with multiple volumes including bind mounts",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "my_data_volume",
						Target: "/data",
						Type:   "volume",
					},
					{
						Source: "/var/log/myapp:/logs",
						Target: "/logs",
						Type:   "bind",
					},
					{
						Source: "~/configs:/app/configs",
						Target: "/app/configs",
						Type:   "",
					},
					{
						Source: "another_volume",
						Type:   "bind",
					},
					{
						Source: "my_data_volume_2",
						Bind: &types.ServiceVolumeBind{
							Propagation: "rprivate",
						},
					},
				},
			},
			expectingThreats: 4,
		},
		{
			name: "service with docker.sock bind mount",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "/var/run/docker.sock:/var/run/docker.sock",
						Target: "/var/run/docker.sock",
						Type:   "bind",
					},
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with docker.sock bind mount using Bind field",
			service: types.ServiceConfig{
				Name: "test_service",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: "/var/run/docker.sock:/var/run/docker.sock",
						Target: "/var/run/docker.sock",
						Bind:   &types.ServiceVolumeBind{},
					},
				},
			},
			expectingThreats: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForBindMounts(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForHardcodedSecrets tests the checkForHardcodedSecrets function
func TestCheckForHardcodedSecrets(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without command and environment",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 0,
		},
		{
			name: "service with empty command and environment",
			service: types.ServiceConfig{
				Name:        "test_service",
				Command:     []string{},
				Environment: map[string]*string{},
			},
			expectingThreats: 0,
		},
		{
			name: "service with no hardcoded secrets",
			service: types.ServiceConfig{
				Name: "test_service",
				Command: []string{
					"run",
					"--port=8080",
					"--mode=production",
				},
				Environment: map[string]*string{
					"ENV":      strPtr("production"),
					"API_KEY":  strPtr(""),
					"password": nil,
				},
			},
			expectingThreats: 0,
		},
		{
			name: "service with one hardcoded secret in command",
			service: types.ServiceConfig{
				Name:    "test_service",
				Command: []string{"run", "--password=secret123"},
			},
			expectingThreats: 1,
		},
		{
			name: "service with one hardcoded secret in environment",
			service: types.ServiceConfig{
				Name: "test_service",
				Environment: map[string]*string{
					"aPI_KeY": strPtr("mysecretapikey"),
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with multiple hardcoded secrets",
			service: types.ServiceConfig{
				Name: "test_service",
				Command: []string{
					"start",
					"--token=secrettoken",
					"password=pass123",
				},
				Environment: map[string]*string{
					"PASSWORD": strPtr("envpass"),
					"USER":     strPtr("admin"),
				},
			},
			expectingThreats: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForHardcodedSecrets(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForPoorLoggingConfiguration tests the checkForPoorLoggingConfiguration function
func TestCheckForPoorLoggingConfiguration(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without logging configuration",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 1,
		},
		{
			name: "service with empty logging configuration",
			service: types.ServiceConfig{
				Name:    "test_service",
				Logging: &types.LoggingConfig{},
			},
			expectingThreats: 1,
		},
		{
			name: "service with logging disabled",
			service: types.ServiceConfig{
				Name: "test_service",
				Logging: &types.LoggingConfig{
					Driver: "none",
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with proper logging configuration",
			service: types.ServiceConfig{
				Name: "test_service",
				Logging: &types.LoggingConfig{
					Driver: "json-file",
				},
			},
			expectingThreats: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForPoorLoggingConfiguration(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForPrivilegedContainers tests the checkForPrivilegedContainers function
func TestCheckForPrivilegedContainers(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without privileged flag",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 0,
		},
		{
			name: "service with privileged flag set to false",
			service: types.ServiceConfig{
				Name:       "test_service",
				Privileged: false,
			},
			expectingThreats: 0,
		},
		{
			name: "service with privileged flag set to true",
			service: types.ServiceConfig{
				Name:       "test_service",
				Privileged: true,
			},
			expectingThreats: 1,
		},
		{
			name: "service with 'all' capability added in cap_add",
			service: types.ServiceConfig{
				Name:   "test_service",
				CapAdd: []string{"ALL"},
			},
			expectingThreats: 1,
		},
		{
			name: "service with other dangerous capabilities added in cap_add",
			service: types.ServiceConfig{
				Name:   "test_service",
				CapAdd: []string{"SYS_ADMIN", "NET_ADMIN"},
			},
			expectingThreats: 2,
		},
		{
			name: "service with multiple privileged settings",
			service: types.ServiceConfig{
				Name:       "test_service",
				Privileged: true,
				CapAdd:     []string{"ALL", "NET_ADMIN"},
			},
			expectingThreats: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForPrivilegedContainers(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForPublishedPorts tests the checkForPublishedPorts function
func TestCheckForPublishedPorts(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without ports",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 0,
		},
		{
			name: "service with one published port",
			service: types.ServiceConfig{
				Name: "test_service",
				Ports: []types.ServicePortConfig{
					{
						Target:    80,
						Published: "8080",
						Protocol:  "tcp",
						Mode:      "ingress",
					},
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with multiple published ports",
			service: types.ServiceConfig{
				Name: "test_service",
				Ports: []types.ServicePortConfig{
					{
						Target:    80,
						Published: "8080",
						Protocol:  "tcp",
						Mode:      "ingress",
					},
					{
						Target:    443,
						Published: "8443",
						Protocol:  "tcp",
						Mode:      "ingress",
					},
					{
						Published: "123",
						Protocol:  "udp",
						Mode:      "ingress",
					},
					{
						Target:   3306,
						Protocol: "tcp",
						Mode:     "ingress",
					},
				},
			},
			expectingThreats: 3, // Only the first 3 ports are published; the 4th is internal-only
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForPublishedPorts(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForRootUser tests the checkForRootUser function
func TestCheckForRootUser(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without specific user",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 1,
		},
		{
			name: "service with non-root user",
			service: types.ServiceConfig{
				Name: "test_service",
				User: "User123",
			},
			expectingThreats: 0,
		},
		{
			name: "service with user set to '0' (root)",
			service: types.ServiceConfig{
				Name: "test_service",
				User: "0",
			},
			expectingThreats: 1,
		},
		{
			name: "service with user set to 'root'",
			service: types.ServiceConfig{
				Name: "test_service",
				User: "root",
			},
			expectingThreats: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForRootUser(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForUnlimitedResources tests the checkForUnlimitedResources function
func TestCheckForUnlimitedResources(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name             string
		service          types.ServiceConfig
		expectingThreats int
	}{
		{
			name: "service without deploy",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreats: 1,
		},
		{
			name: "service with deploy but no resources",
			service: types.ServiceConfig{
				Name:   "test_service",
				Deploy: &types.DeployConfig{},
			},
			expectingThreats: 1,
		},
		{
			name: "service with resources but no limits",
			service: types.ServiceConfig{
				Name: "test_service",
				Deploy: &types.DeployConfig{
					Resources: types.Resources{},
				},
			},
			expectingThreats: 1,
		},
		{
			name: "service with limits set",
			service: types.ServiceConfig{
				Name: "test_service",
				Deploy: &types.DeployConfig{
					Resources: types.Resources{
						Limits: &types.Resource{
							MemoryBytes: 512 * 1024 * 1024,
							NanoCPUs:    1 * 1e9,
						},
					},
				},
			},
			expectingThreats: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForUnlimitedResources(tt.service)
			assert.Equal(t, tt.expectingThreats, len(threats), "Expected %d threats but got %d", tt.expectingThreats, len(threats))
		})
	}
}

// TestCheckForUnspecificImageVersion tests the checkForUnspecificImageVersion function
func TestCheckForUnspecificImageVersion(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name            string
		service         types.ServiceConfig
		expectingThreat bool
	}{
		{
			name: "service without image",
			service: types.ServiceConfig{
				Name: "test_service",
			},
			expectingThreat: false,
		},
		{
			name: "image with specific version tag",
			service: types.ServiceConfig{
				Name:  "test_service",
				Image: "nginx:1.21.0",
			},
			expectingThreat: true,
		},
		{
			name: "image with specific version tag and digest",
			service: types.ServiceConfig{
				Name:  "test_service",
				Image: "nginx:1.21.0@sha256:1234example",
			},
			expectingThreat: false,
		},
		{
			name: "image without version tag",
			service: types.ServiceConfig{
				Name:  "test_service",
				Image: "nginx",
			},
			expectingThreat: true,
		},
		{
			name: "image with 'latest' tag in lowercase",
			service: types.ServiceConfig{
				Name:  "test_service",
				Image: "nginx:latest",
			},
			expectingThreat: true,
		},
		{
			name: "image with 'latest' tag in mixed case",
			service: types.ServiceConfig{
				Name:  "test_service",
				Image: "nginx:LatESt",
			},
			expectingThreat: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := threatInvestigator.checkForUnspecificImageVersion(tt.service)
			if tt.expectingThreat {
				assert.Equal(t, len(threats), 1, "Expected one threat but got %d", len(threats))
			} else {
				assert.Equal(t, len(threats), 0, "Expected no threats but got %d", len(threats))
			}
		})
	}
}

// TestGenerateThreat tests the generateThreat function to ensure it creates Threat instances correctly.
func TestGenerateThreat(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name        string
		serviceName string
		threatTitle string
		threatType  common.ThreatType
		description string
		mitigation  string
	}{
		{
			name:        "Threat with valid inputs",
			serviceName: "test_service",
			threatTitle: "Spoofing Threat",
			threatType:  common.Spoofing,
			description: "This is a test threat description.",
			mitigation:  "This is a test threat mitigation.",
		},
		{
			name:        "Threat with empty inputs",
			serviceName: "",
			threatTitle: "",
			threatType:  common.ThreatTypeUnknown,
			description: "",
			mitigation:  "",
		},
		{
			name:        "Threat with long inputs",
			serviceName: "a_very_long_service_name_that_exceeds_normal_lengths",
			threatTitle: "A Very Long Threat Title That Exceeds Normal Lengths",
			threatType:  common.InformationDisclosure,
			description: "This is a very long threat description meant to test the handling of long strings within the threat generation function. It should be able to handle descriptions of arbitrary length without any issues.",
			mitigation:  "This is a very long threat mitigation meant to test the handling of long strings within the threat generation function. It should be able to handle mitigations of arbitrary length without any issues.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threat := threatInvestigator.generateThreat(tt.serviceName, tt.threatTitle, tt.threatType, tt.description, tt.mitigation)
			assert.NotEmpty(t, threat.InternalID, "Internal Threat ID shozld not be empty")
			assert.NotEmpty(t, threat.ID, "Threat ID should not be empty")
			assert.Equal(t, tt.threatTitle, threat.Title, "Threat title should match")
			assert.Equal(t, common.Open, threat.Status, "Threat status should be Open")
			assert.Equal(t, "TBD", threat.Severity, "Threat severity should be 'TBD'")
			assert.Equal(t, tt.threatType, threat.Type, "Threat type should match")
			assert.Contains(t, threat.Description, tt.description, "Threat description should contain the input description")
			assert.Equal(t, tt.mitigation, threat.Mitigation, "Threat mitigation should match")
			assert.Equal(t, common.STRIDE, threat.ModelType, "Threat model type should be STRIDE")
			assert.Equal(t, threat.Number, int64(0), "Threat number should be 0")
			assert.Equal(t, "", threat.Score, "Threat score should be empty")
			assert.False(t, threat.IsGeneratedByUser, "Threat should not be generated by user")
			assert.Equal(t, common.DataSourceDockerCompose, threat.Source, "Threat source should be DataSourceDockerCompose")
			assert.Equal(t, -1, threat.MapIndex, "Threat MapIndex should be -1")
		})
	}
}

// TestGenerateThreatIDHash tests the generateThreatIDHash function to ensure it produces non-empty hashes and equal hashes for same input.
func TestGenerateThreatIDHash(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		threatTitle string
		expectedLen int
	}{
		{
			name:        "Valid service name and threat title",
			serviceName: "test_service",
			threatTitle: "Sample Threat",
			expectedLen: common.MaxIDHashLength,
		},
		{
			name:        "Empty service name and threat title",
			serviceName: "",
			threatTitle: "",
			expectedLen: common.MaxIDHashLength,
		},
		{
			name:        "Long service name and threat title",
			serviceName: "a_very_long_service_name_that_exceeds_normal_lengths",
			threatTitle: "A Very Long Threat Title That Exceeds Normal Lengths",
			expectedLen: common.MaxIDHashLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := generateThreatIDHash(tt.serviceName, tt.threatTitle)
			secondHash := generateThreatIDHash(tt.serviceName, tt.threatTitle) // Generate a second hash for comparison
			assert.Equal(t, hash, secondHash, "Hashes should be equal for the same input")
			assert.NotEmpty(t, hash, "Hash should not be empty")
			assert.Equal(t, tt.expectedLen, len(hash), fmt.Sprintf("Hash length should be %d characters", tt.expectedLen))
		})
	}
}

// TestIsDockerSocket tests the isDockerSocket function
func TestIsDockerSocket(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "Path with docker.sock",
			path:     "/var/run/docker.sock:/var/run/docker.sock",
			expected: true,
		},
		{
			name:     "Path without docker.sock",
			path:     "/var/log/myapp:/logs",
			expected: false,
		},
		{
			name:     "No path",
			expected: false,
		},
		{
			name:     "Empty path",
			path:     "",
			expected: false,
		},
		{
			name:     "Path with similar name",
			path:     "/var/run/docker-sock:/var/run/docker-sock",
			expected: false,
		},
		{
			name:     "Path with only docker.sock",
			path:     "/var/run/docker.sock",
			expected: true,
		},
		{
			name:     "Path with docker.sock in the middle",
			path:     "/some/path/docker.sock/another/path",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := threatInvestigator.isDockerSocket(tt.path)
			assert.Equal(t, tt.expected, result, "Expected isDockerSocket(%q) to be %v, got %v", tt.path, tt.expected, result)
		})
	}
}

// TestIsHostPath tests the isHostPath function
func TestIsHostPath(t *testing.T) {
	threatInvestigator := NewDockerComposeThreatInvestigator(slog.Default())
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "Path starting with /",
			path:     "/var/log/myapp:/logs",
			expected: true,
		},
		{
			name:     "Path starting with ./",
			path:     "./src:/app/src",
			expected: true,
		},
		{
			name:     "Path starting with ../",
			path:     "../data:/app/data",
			expected: true,
		},
		{
			name:     "Path starting with ~/",
			path:     "~/configs:/app/configs",
			expected: true,
		},
		{
			name:     "Path without host indicators",
			path:     "postgres_data:/var/lib/postgresql/data",
			expected: false,
		},
		{
			name:     "Empty path",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := threatInvestigator.isHostPath(tt.path)
			assert.Equal(t, tt.expected, result, "Expected isHostPath(%q) to be %v, got %v", tt.path, tt.expected, result)
		})
	}
}

// strPtr is a helper function to create a pointer to a string
func strPtr(s string) *string {
	return &s
}
