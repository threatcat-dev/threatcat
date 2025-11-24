package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGenerateIDHash tests the generateIDHash function to ensure it produces non-empty hashes and equal hashes for same input.
func TestGenerateIDHash(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		serviceName string
	}{
		{
			name:        "Valid file path and service name",
			filePath:    "/path/to/docker-compose.yml",
			serviceName: "web",
		},
		{
			name:        "Empty file path and service name",
			filePath:    "",
			serviceName: "",
		},
		{
			name:        "Long file path and service name",
			filePath:    "/a/very/long/path/to/a/docker-compose/file/that/should/be/hashed",
			serviceName: "very-long-service-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := GenerateIDHash(tt.filePath, tt.serviceName)
			secondHash := GenerateIDHash(tt.filePath, tt.serviceName) // Generate a second hash for comparison
			assert.Equal(t, hash, secondHash, "Hashes should be equal for the same input")
			assert.NotEmpty(t, hash, "Hash should not be empty")
			assert.Equal(t, MaxIDHashLength, len(hash), fmt.Sprintf("Hash length should be %d characters", MaxIDHashLength))
		})
	}
}
